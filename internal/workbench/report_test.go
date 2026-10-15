package workbench

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestReportPathOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		change       func([]Bundle) []Bundle
		want, absent string
	}{
		{"disabled", func(b []Bundle) []Bundle { disabled(b); return b }, "Forwarding disabled", "Forwarding enabled"},
		{"reversed", func(b []Bundle) []Bundle { disabled(b); return []Bundle{b[1], b[0]} }, "Forwarding disabled", "Forwarding enabled"},
		{"missing", func(b []Bundle) []Bundle { return b[:1] }, "Not collected", "Forwarding enabled"},
		{"stale", func(b []Bundle) []Bundle { set(&b[1], "forwarding", Stale, Facts{}); return b }, "Stale", "Forwarding enabled"},
		{"denied", func(b []Bundle) []Bundle { set(&b[1], "forwarding", Denied, Facts{}); return b }, "Permission denied", "Forwarding enabled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Report(&out, Incident{Bundles: tc.change(fixture())}); err != nil {
				t.Fatal(err)
			}
			path := strings.Split(strings.Split(out.String(), `<div class="path">`)[1], `<h2 id="findings">`)[0]
			if !strings.Contains(path, tc.want) || strings.Contains(path, tc.absent) {
				t.Fatalf("incorrect path outcome: %s", path)
			}
		})
	}
}

func TestReportEvidenceLabelsAndEscaping(t *testing.T) {
	b := fixture()
	disabled(b)
	b[0].Target.Host = strings.Repeat("long", 60) + "<tag>"
	b[1].Target = b[0].Target
	b[0].ID = strings.Repeat("a", 128)
	var out bytes.Buffer
	if err := Report(&out, Incident{Bundles: b}); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	found := false
	for _, match := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(html, -1) {
		target, err := url.PathUnescape(match[1])
		if err != nil {
			t.Fatal(err)
		}
		if target == b[0].ID+"/tcp" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing source TCP evidence link")
	}
	for _, want := range []string{`id="` + b[0].ID + `/tcp"`, `>Source / TCP</a>`, `>Router / Forwarding</a>`, `Forwarding: false`, `&lt;tag&gt;`, `Error · Supported hypothesis`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing report content %q", want)
		}
	}
	if strings.Contains(html, "<tag>") {
		t.Fatal("unescaped host")
	}
}
