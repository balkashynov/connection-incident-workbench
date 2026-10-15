package workbench

import (
	_ "embed"
	"html/template"
	"io"
	"strings"
)

func Report(w io.Writer, in Incident) error {
	verified, err := Analyze(in.Bundles)
	if err != nil {
		return err
	}
	return reportTemplate.Execute(w, verified)
}

//go:embed report.html
var reportHTML string

var reportTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"ref": ref, "obs": observation, "bundle": reportBundle, "label": reportLabel,
	"outcome": reportOutcome, "evidenceLabel": reportEvidenceLabel,
}).Parse(reportHTML))

func reportBundle(bundles []Bundle, role string) *Bundle {
	for i := range bundles {
		if bundles[i].Role == role {
			return &bundles[i]
		}
	}
	return nil
}

func reportLabel(value any) string {
	s := strings.ReplaceAll(stringValue(value), "_", " ")
	if s == "" {
		return "Unknown"
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func stringValue(value any) string {
	if state, ok := value.(State); ok {
		return string(state)
	}
	s, _ := value.(string)
	return s
}

func reportOutcome(o Observation) string {
	if o.State == Failed && o.Facts.TCP == "refused" {
		return "Connection refused"
	}
	if o.State != Observed {
		return reportLabel(o.State)
	}
	switch o.Kind {
	case "dns_os", "dns_tailscale":
		return "Resolved"
	case "peer":
		return "Peer replied"
	case "tcp":
		return "Connected"
	case "forwarding":
		if o.Facts.Enabled != nil && !*o.Facts.Enabled {
			return "Forwarding disabled"
		}
		return "Forwarding enabled"
	default:
		return reportLabel(o.State)
	}
}

func reportEvidenceLabel(bundles []Bundle, evidence string) string {
	for _, b := range bundles {
		for _, o := range b.Observations {
			if ref(b, o) == evidence {
				kind := map[string]string{"daemon": "Daemon", "dns_os": "OS DNS", "dns_tailscale": "Tailscale DNS", "peer": "Peer", "tcp": "TCP", "forwarding": "Forwarding"}[o.Kind]
				return reportLabel(b.Role) + " / " + kind
			}
		}
	}
	return evidence
}
