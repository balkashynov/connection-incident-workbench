// Package workbench separates collection, evidence validation and offline interpretation.
package workbench

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"time"
)

const Version = "0.1.0"
const MaxBytes = 2 << 20

type State string

const (
	Observed     State = "observed"
	Failed       State = "failed"
	Denied       State = "permission_denied"
	Unsupported  State = "unsupported"
	TimedOut     State = "timed_out"
	Stale        State = "stale"
	NotCollected State = "not_collected"
)

type Target struct {
	Host    string `json:"host"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

// Facts is an allowlist. Raw LocalAPI replies, errors and preferences never cross this boundary.
type Facts struct {
	Backend       string   `json:"backend,omitempty"`
	DaemonVersion string   `json:"daemon_version,omitempty"`
	Node          string   `json:"node,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	Path          string   `json:"path,omitempty"`
	TCP           string   `json:"tcp,omitempty"`
	Enabled       *bool    `json:"enabled,omitempty"`
}

type Observation struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Method     string    `json:"method"`
	State      State     `json:"state"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	DurationMS int64     `json:"duration_ms"`
	ErrorCode  string    `json:"error_code,omitempty"`
	Facts      Facts     `json:"facts"`
}

type Bundle struct {
	SchemaVersion int           `json:"schema_version"`
	ToolVersion   string        `json:"tool_version"`
	ClientVersion string        `json:"client_version"`
	ID            string        `json:"bundle_id"`
	IncidentID    string        `json:"incident_id"`
	Role          string        `json:"role"`
	Platform      string        `json:"platform"`
	Machine       string        `json:"machine"`
	Router        string        `json:"selected_router,omitempty"`
	Target        Target        `json:"target"`
	Start         time.Time     `json:"start"`
	End           time.Time     `json:"end"`
	Synthetic     bool          `json:"synthetic"`
	Redaction     string        `json:"redaction"`
	Observations  []Observation `json:"observations"`
}

type Finding struct {
	RuleID       string   `json:"rule_id"`
	RuleVersion  int      `json:"rule_version"`
	Severity     string   `json:"severity"`
	Category     string   `json:"category"`
	Summary      string   `json:"summary"`
	Evidence     []string `json:"evidence"`
	Alternatives []string `json:"alternatives"`
	NextCheck    string   `json:"next_check"`
}

type Incident struct {
	SchemaVersion int       `json:"schema_version"`
	Bundles       []Bundle  `json:"bundles"`
	Findings      []Finding `json:"findings"`
	Limitations   []string  `json:"limitations"`
}

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
var versionPattern = regexp.MustCompile(`^[a-zA-Z0-9.+_-]{1,100}$`)
var methods = map[string]string{
	"daemon": "localapi.status", "peer": "localapi.ping.disco", "dns_os": "os.lookup_ip",
	"dns_tailscale": "localapi.query_dns", "tcp": "os.tcp_dial", "forwarding": "linux.proc_sys",
}

func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func identifier(s string) bool { return len(s) > 0 && len(s) <= 253 }

func (b Bundle) Validate() error {
	bad := func(s string) error { return fmt.Errorf("invalid bundle: %s", s) }
	if b.SchemaVersion != 1 {
		return bad("unsupported schema version")
	}
	if !idPattern.MatchString(b.ID) || !idPattern.MatchString(b.IncidentID) {
		return bad("identifier")
	}
	if !versionPattern.MatchString(b.ToolVersion) || !versionPattern.MatchString(b.ClientVersion) {
		return bad("version")
	}
	if !oneOf(b.Role, "source", "router") || !oneOf(b.Platform, "linux", "darwin", "windows", "synthetic") {
		return bad("role/platform")
	}
	if !oneOf(b.Redaction, "local", "pseudonymized") {
		return bad("redaction mode")
	}
	if !identifier(b.Machine) || !identifier(b.Target.Host) || !identifier(b.Target.Address) || (b.Router != "" && !identifier(b.Router)) || b.Target.Port == 0 {
		return bad("machine/target")
	}
	if b.Redaction == "local" {
		if _, err := netip.ParseAddr(b.Target.Address); err != nil {
			return bad("explicit target IP required")
		}
		if b.Router != "" {
			if _, err := netip.ParseAddr(b.Router); err != nil {
				return bad("router IP")
			}
		}
	}
	if b.Start.IsZero() || b.End.Before(b.Start) || b.End.Sub(b.Start) > time.Hour {
		return bad("collection window")
	}
	if len(b.Observations) > 32 {
		return bad("observation limit")
	}
	ids, kinds := map[string]bool{}, map[string]bool{}
	for _, o := range b.Observations {
		if !idPattern.MatchString(o.ID) || ids[o.ID] || kinds[o.Kind] {
			return bad("duplicate/invalid observation")
		}
		ids[o.ID] = true
		kinds[o.Kind] = true
		if methods[o.Kind] == "" || methods[o.Kind] != o.Method {
			return bad("probe kind/method")
		}
		if !oneOf(string(o.State), string(Observed), string(Failed), string(Denied), string(Unsupported), string(TimedOut), string(Stale), string(NotCollected)) {
			return bad("observation state")
		}
		if o.Start.Before(b.Start) || o.End.After(b.End) || o.End.Before(o.Start) || o.DurationMS < 0 || o.DurationMS > 3600000 {
			return bad("probe time")
		}
		if !oneOf(o.ErrorCode, "", "permission_denied", "timeout", "unavailable", "refused", "lookup_failed", "probe_failed", "unsupported", "not_requested") {
			return bad("error code")
		}
		if len(o.Facts.Addresses) > 64 || len(o.Facts.Node) > 253 {
			return bad("facts size")
		}
		for _, a := range o.Facts.Addresses {
			if len(a) > 253 {
				return bad("address size")
			}
			if b.Redaction == "local" {
				if _, err := netip.ParseAddr(a); err != nil {
					return bad("address")
				}
			}
		}
		if o.Facts.Backend != "" && !oneOf(o.Facts.Backend, "NoState", "NeedsLogin", "NeedsMachineAuth", "Stopped", "Starting", "Running", "InUseOtherUser", "unknown") {
			return bad("backend")
		}
		if o.Facts.DaemonVersion != "" && !versionPattern.MatchString(o.Facts.DaemonVersion) {
			return bad("daemon version")
		}
		if !oneOf(o.Facts.Path, "", "direct", "derp", "peer_relay", "unknown") || !oneOf(o.Facts.TCP, "", "connected", "refused", "timeout", "failed") {
			return bad("fact enum")
		}
		// Reject facts misplaced under another probe, rather than interpreting an arbitrary JSON payload.
		f := o.Facts
		if (f.Backend != "" || f.DaemonVersion != "") && o.Kind != "daemon" || f.Node != "" && !oneOf(o.Kind, "daemon", "peer") || len(f.Addresses) > 0 && !oneOf(o.Kind, "dns_os", "dns_tailscale") || f.Path != "" && o.Kind != "peer" || f.TCP != "" && o.Kind != "tcp" || f.Enabled != nil && o.Kind != "forwarding" {
			return bad("misplaced facts")
		}
		if o.State == Observed {
			switch o.Kind {
			case "daemon":
				if f.Backend == "" {
					return bad("missing backend")
				}
			case "peer":
				if f.Node == "" || f.Path == "" {
					return bad("missing peer")
				}
			case "dns_os", "dns_tailscale":
				if len(f.Addresses) == 0 {
					return bad("missing addresses")
				}
			case "tcp":
				if f.TCP != "connected" {
					return bad("TCP success")
				}
			case "forwarding":
				if f.Enabled == nil {
					return bad("missing forwarding")
				}
			}
		} else if f.TCP == "connected" || f.Enabled != nil || f.Backend != "" || f.Node != "" || len(f.Addresses) > 0 || f.Path != "" || f.DaemonVersion != "" {
			return bad("facts on unavailable probe")
		}
		if o.Kind == "tcp" && (o.State == TimedOut && f.TCP != "timeout" || o.State == Failed && !oneOf(f.TCP, "refused", "failed")) {
			return bad("TCP failure")
		}
	}
	return nil
}

func Decode(r io.Reader, out any) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxBytes {
		return errors.New("input exceeds 2 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(out); err != nil {
		return err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
