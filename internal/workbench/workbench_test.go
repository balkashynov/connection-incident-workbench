package workbench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() []Bundle {
	at := time.Date(2026, 10, 14, 20, 0, 0, 0, time.UTC)
	enabled := true
	makeBundle := func(role string) Bundle {
		b := Bundle{SchemaVersion: 1, ToolVersion: Version, ClientVersion: "1.104.1", ID: role, IncidentID: "case-1", Role: role, Platform: "synthetic", Machine: "100.64.0.1", Target: Target{"db.internal", "192.0.2.10", 5432}, Start: at, End: at.Add(10 * time.Second), Synthetic: true, Redaction: "local"}
		facts := map[string]Facts{"daemon": {Backend: "Running", Node: b.Machine}, "dns_os": {Addresses: []string{b.Target.Address}}, "dns_tailscale": {Addresses: []string{b.Target.Address}}, "peer": {Node: "100.64.0.2", Path: "direct"}, "tcp": {TCP: "connected"}, "forwarding": {Enabled: &enabled}}
		for _, kind := range []string{"daemon", "dns_os", "dns_tailscale", "peer", "tcp", "forwarding"} {
			b.Observations = append(b.Observations, Observation{ID: kind, Kind: kind, Method: methods[kind], State: Observed, Start: at, End: at.Add(time.Second), DurationMS: 1000, Facts: facts[kind]})
		}
		return b
	}
	s, r := makeBundle("source"), makeBundle("router")
	s.Router = "100.64.0.2"
	r.Machine = s.Router
	r.Observations[0].Facts.Node = r.Machine
	return []Bundle{s, r}
}
func set(b *Bundle, kind string, state State, f Facts) {
	for i := range b.Observations {
		if b.Observations[i].Kind == kind {
			b.Observations[i].State = state
			b.Observations[i].Facts = f
		}
	}
}
func has(in Incident, id string) bool {
	for _, f := range in.Findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
func analyzeTest(t *testing.T, b []Bundle) Incident {
	t.Helper()
	in, err := Analyze(b)
	if err != nil {
		t.Fatal(err)
	}
	return in
}
func disabled(b []Bundle) {
	v := false
	set(&b[1], "forwarding", Observed, Facts{Enabled: &v})
	set(&b[0], "tcp", TimedOut, Facts{TCP: "timeout"})
}

func TestDiagnosticScenarios(t *testing.T) {
	tests := []struct {
		name         string
		change       func([]Bundle) []Bundle
		want, absent []string
	}{
		{"H1 healthy", func(b []Bundle) []Bundle { return b }, []string{"source.tcp_connected"}, []string{"source.tcp_unresolved", "path.forwarding_hypothesis"}},
		{"R1 forwarding disabled", func(b []Bundle) []Bundle { disabled(b); return b }, []string{"router.forwarding_disabled", "path.forwarding_hypothesis", "source.tcp_unresolved"}, []string{"source.tcp_connected"}},
		{"U1 missing router", func(b []Bundle) []Bundle { disabled(b); return b[:1] }, []string{"source.tcp_unresolved"}, []string{"router.forwarding_disabled", "path.forwarding_hypothesis"}},
		{"D1 source DNS", func(b []Bundle) []Bundle { set(&b[0], "dns_os", Failed, Facts{}); return b }, []string{"source.dns_failure", "path.source_dns_difference"}, []string{"source.tcp_unresolved"}},
		{"P1 denied API DNS", func(b []Bundle) []Bundle { set(&b[0], "dns_tailscale", Denied, Facts{}); return b }, []string{"source.tcp_connected", "coverage.source.dns_tailscale"}, []string{"source.dns_failure", "path.source_dns_difference"}},
		{"S1 refusal", func(b []Bundle) []Bundle {
			set(&b[0], "tcp", Failed, Facts{TCP: "refused"})
			set(&b[1], "tcp", Failed, Facts{TCP: "refused"})
			return b
		}, []string{"router.tcp_refused"}, []string{"path.forwarding_hypothesis"}},
		{"timeout not refusal", func(b []Bundle) []Bundle { set(&b[1], "tcp", TimedOut, Facts{TCP: "timeout"}); return b }, nil, []string{"router.tcp_refused"}},
		{"T1 distant windows", func(b []Bundle) []Bundle {
			disabled(b)
			b[1].Start = b[1].Start.Add(time.Hour)
			b[1].End = b[1].End.Add(time.Hour)
			for i := range b[1].Observations {
				b[1].Observations[i].Start = b[1].Observations[i].Start.Add(time.Hour)
				b[1].Observations[i].End = b[1].Observations[i].End.Add(time.Hour)
			}
			return b
		}, []string{"correlation.window_gap", "router.forwarding_disabled"}, []string{"path.forwarding_hypothesis"}},
		{"wrong DNS answer", func(b []Bundle) []Bundle {
			set(&b[0], "dns_os", Observed, Facts{Addresses: []string{"192.0.2.99"}})
			return b
		}, []string{"source.address_mismatch"}, []string{"path.source_dns_difference"}},
		{"stale forwarding", func(b []Bundle) []Bundle { disabled(b); set(&b[1], "forwarding", Stale, Facts{}); return b }, []string{"coverage.router.forwarding"}, []string{"router.forwarding_disabled", "path.forwarding_hypothesis"}},
		{"wrong ping recipient", func(b []Bundle) []Bundle {
			disabled(b)
			set(&b[0], "peer", Observed, Facts{Node: "100.64.0.99", Path: "direct"})
			return b
		}, []string{"router.forwarding_disabled"}, []string{"path.forwarding_hypothesis"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := analyzeTest(t, tc.change(fixture()))
			for _, id := range tc.want {
				if !has(in, id) {
					t.Errorf("missing %s", id)
				}
			}
			for _, id := range tc.absent {
				if has(in, id) {
					t.Errorf("unexpected %s", id)
				}
			}
			refs := map[string]bool{}
			for _, b := range in.Bundles {
				for _, o := range b.Observations {
					refs[ref(b, o)] = true
				}
			}
			for _, f := range in.Findings {
				for _, r := range f.Evidence {
					if !refs[r] {
						t.Errorf("dangling evidence %s", r)
					}
				}
			}
		})
	}
}
func TestRejectMismatchedBundles(t *testing.T) {
	for _, field := range []string{"incident", "router", "address", "port", "host", "provenance", "redaction", "bundle"} {
		t.Run(field, func(t *testing.T) {
			b := fixture()
			switch field {
			case "incident":
				b[1].IncidentID = "different"
			case "router":
				b[1].Machine = "100.64.0.99"
			case "address":
				b[1].Target.Address = "192.0.2.99"
			case "port":
				b[1].Target.Port = 80
			case "host":
				b[1].Target.Host = "different"
			case "provenance":
				b[1].Synthetic = false
			case "redaction":
				b[1].Redaction = "pseudonymized"
			case "bundle":
				b[1].ID = b[0].ID
			}
			if _, err := Analyze(b); err == nil {
				t.Fatal("accepted mismatched evidence")
			}
		})
	}
}
func TestExportCorrelationAndOmission(t *testing.T) {
	b := fixture()
	disabled(b)
	in := analyzeTest(t, b)
	in.Findings = append(in.Findings, Finding{Summary: "injected secret-token"})
	out, err := Redact(in)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(out)
	for _, s := range []string{"db.internal", "192.0.2.10", "100.64.0.1", "100.64.0.2", "secret-token", "case-1"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("leaked %s", s)
		}
	}
	if out.Bundles[0].Router != out.Bundles[1].Machine || out.Bundles[0].Target != out.Bundles[1].Target {
		t.Fatal("broken correlation")
	}
	if !has(out, "path.forwarding_hypothesis") {
		t.Fatal("lost diagnosis")
	}
	twice, err := Redact(out)
	if err != nil {
		t.Fatal(err)
	}
	if !has(twice, "path.forwarding_hypothesis") {
		t.Fatal("lost repeated-export diagnosis")
	}
}
func TestReportEscapesInputAndRecomputesFindings(t *testing.T) {
	b := fixture()
	b[0].Target.Host = `<img src=x onerror="alert(1)">`
	b[1].Target = b[0].Target
	in := analyzeTest(t, b)
	in.Findings = []Finding{{Summary: "fabricated diagnosis"}}
	var out bytes.Buffer
	if err := Report(&out, in); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<img") || strings.Contains(out.String(), "fabricated diagnosis") || strings.Contains(out.String(), "<script") {
		t.Fatal("unsafe report")
	}
	if !strings.Contains(out.String(), "&lt;img") {
		t.Fatal("test text missing")
	}
}
func TestDecodeBoundsAndValidation(t *testing.T) {
	for _, s := range []string{`{"unknown":1}`, `{} {}`, strings.Repeat(" ", MaxBytes+1)} {
		var b Bundle
		if err := Decode(strings.NewReader(s), &b); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	for _, field := range []string{"schema", "duplicate", "state", "facts", "time", "count", "tcp"} {
		t.Run(field, func(t *testing.T) {
			b := fixture()[0]
			switch field {
			case "schema":
				b.SchemaVersion = 2
			case "duplicate":
				b.Observations = append(b.Observations, b.Observations[0])
			case "state":
				b.Observations[0].State = "ok"
			case "facts":
				b.Observations[0].Facts.TCP = "connected"
			case "time":
				b.Observations[0].End = b.End.Add(time.Hour)
			case "count":
				b.Observations = make([]Observation, 33)
			case "tcp":
				set(&b, "tcp", Failed, Facts{TCP: "connected"})
			}
			if b.Validate() == nil {
				t.Fatal("accepted invalid bundle")
			}
		})
	}
}
func TestLocalAPIDenialPreservesOSChecks(t *testing.T) {
	dir, err := os.MkdirTemp("", "tcw-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "permission denied: sensitive.example", http.StatusForbidden)
	})}
	go server.Serve(l)
	defer server.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	port := uint16(tcp.Addr().(*net.TCPAddr).Port)
	b, err := Collect(context.Background(), CollectOptions{Role: "source", IncidentID: "denied", Host: "127.0.0.1", Address: "127.0.0.1", Port: port, Socket: socket, Router: "100.64.0.2", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if observation(b, "daemon").State != Denied || observation(b, "peer").State != Denied || !success(observation(b, "tcp")) || !success(observation(b, "dns_os")) {
		t.Fatalf("unexpected states: %+v", b.Observations)
	}
	data, _ := json.Marshal(b)
	if strings.Contains(string(data), "sensitive.example") {
		t.Fatal("raw API error leaked")
	}
}
func TestLocalAPIAdapterAllowlist(t *testing.T) {
	dir, err := os.MkdirTemp("", "tcw-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/localapi/v0/status":
			fmt.Fprint(w, `{"Version":"1.104.1","BackendState":"Running","TailscaleIPs":["100.64.0.1"],"AuthURL":"https://secret.example/login","User":{"1":{"LoginName":"private-user"}}}`)
		case "/localapi/v0/ping":
			fmt.Fprint(w, `{"IP":"100.64.0.2","NodeIP":"100.64.0.2","Endpoint":"private.example:1234"}`)
		default:
			http.Error(w, "not implemented", 404)
		}
	})}
	go server.Serve(l)
	defer server.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	b, err := Collect(context.Background(), CollectOptions{Role: "source", IncidentID: "adapter", Host: "127.0.0.1", Address: "127.0.0.1", Port: uint16(tcp.Addr().(*net.TCPAddr).Port), Socket: socket, Router: "100.64.0.2", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if b.Machine != "100.64.0.1" || observation(b, "peer").Facts.Path != "direct" {
		t.Fatalf("bad adapter: %+v", b)
	}
	data, _ := json.Marshal(b)
	for _, s := range []string{"secret.example", "private-user", "private.example"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("leak %s", s)
		}
	}
}
