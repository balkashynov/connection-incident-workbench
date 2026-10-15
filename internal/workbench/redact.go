package workbench

import (
	"encoding/json"
	"fmt"
)

// Redact operates on the whole incident. No map, salt or original identity is exported.
// Free-form findings from input are discarded and recomputed from typed evidence.
func Redact(in Incident) (Incident, error) {
	if _, err := Analyze(in.Bundles); err != nil {
		return Incident{}, err
	}
	data, _ := json.Marshal(in.Bundles)
	var bundles []Bundle
	_ = json.Unmarshal(data, &bundles)
	mapping := map[string]string{}
	pseudonym := func(s string) string { return s }
	pseudonym = func(s string) string {
		if s == "" {
			return ""
		}
		if p, ok := mapping[s]; ok {
			return p
		}
		p := fmt.Sprintf("entity-%d", len(mapping)+1)
		mapping[s] = p
		return p
	}
	for i := range bundles {
		b := &bundles[i]
		b.ID = fmt.Sprintf("bundle-%d", i+1)
		b.IncidentID = "incident-1"
		b.Machine = pseudonym(b.Machine)
		b.Router = pseudonym(b.Router)
		b.Target.Host = pseudonym(b.Target.Host)
		b.Target.Address = pseudonym(b.Target.Address)
		b.ToolVersion = Version
		b.ClientVersion = "omitted"
		b.Redaction = "pseudonymized"
		for j := range b.Observations {
			o := &b.Observations[j]
			o.ID = o.Kind
			o.Facts.Node = pseudonym(o.Facts.Node)
			if o.Facts.DaemonVersion != "" {
				o.Facts.DaemonVersion = "omitted"
			}
			for k, a := range o.Facts.Addresses {
				o.Facts.Addresses[k] = pseudonym(a)
			}
		}
	}
	return Analyze(bundles)
}
