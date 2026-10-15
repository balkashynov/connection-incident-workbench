package workbench

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

func observation(b Bundle, kind string) Observation {
	for _, o := range b.Observations {
		if o.Kind == kind {
			return o
		}
	}
	return Observation{Kind: kind, State: NotCollected}
}
func ref(b Bundle, o Observation) string { return b.ID + "/" + o.ID }
func success(o Observation) bool         { return o.State == Observed }
func probeFailure(o Observation) bool    { return o.State == Failed || o.State == TimedOut }

// Analyze is pure: it neither reads the clock nor executes probes. Findings describe the saved windows.
func Analyze(bundles []Bundle) (Incident, error) {
	in := Incident{SchemaVersion: 1, Bundles: bundles, Findings: []Finding{}, Limitations: []string{
		"This is a logical check path, not a packet trace. Router selection is supplied by the operator.",
		"Route approval, effective access policy, application health and destination listener state were not collected.",
		"Checks describe saved collection windows. Machine clocks are not assumed synchronized; no causal ordering is inferred.",
	}}
	if len(bundles) < 1 || len(bundles) > 2 {
		return in, errors.New("provide one source and at most one router bundle")
	}
	var src, router *Bundle
	seen := map[string]bool{}
	for i := range bundles {
		b := &bundles[i]
		if err := b.Validate(); err != nil {
			return in, err
		}
		if seen[b.ID] {
			return in, errors.New("duplicate bundle ID")
		}
		seen[b.ID] = true
		if b.Role == "source" {
			if src != nil {
				return in, errors.New("duplicate source")
			}
			src = b
		} else {
			if router != nil {
				return in, errors.New("duplicate router")
			}
			router = b
		}
	}
	if src == nil {
		return in, errors.New("source bundle required")
	}
	add := func(rule, severity, category, summary, next string, refs []string, alternatives ...string) {
		in.Findings = append(in.Findings, Finding{RuleID: rule, RuleVersion: 1, Severity: severity, Category: category, Summary: summary, NextCheck: next, Evidence: refs, Alternatives: alternatives})
	}
	for _, b := range bundles {
		for _, o := range b.Observations {
			if oneOf(string(o.State), string(Denied), string(Unsupported), string(NotCollected), string(Stale)) && o.ErrorCode != "not_requested" {
				add("coverage."+b.Role+"."+o.Kind, "info", "inconclusive", fmt.Sprintf("%s %s evidence is %s.", b.Role, o.Kind, o.State), "Collect this observation only if it discriminates the remaining explanations.", []string{ref(b, o)})
			}
		}
	}
	tcp := observation(*src, "tcp")
	dns := observation(*src, "dns_os")
	peer := observation(*src, "peer")
	if success(tcp) {
		add("source.tcp_connected", "info", "healthy_check", "The explicit destination IP accepted a TCP connection from the source.", "Check the application protocol separately if requests still fail.", []string{ref(*src, tcp)}, "A TCP handshake does not verify an application response or name resolution.")
	}
	if success(dns) && !slices.Contains(dns.Facts.Addresses, src.Target.Address) {
		add("source.address_mismatch", "warning", "inconclusive", "The requested name resolved, but not to the explicitly tested IP.", "Confirm the intended destination IP and repeat the test against a resolved address.", []string{ref(*src, dns)}, "DNS load balancing, stale records or an incorrect operator-supplied IP.")
	}
	if dns.State == Failed && success(tcp) {
		refs := []string{ref(*src, dns), ref(*src, tcp)}
		add("source.dns_failure", "warning", "supported_hypothesis", "Source name resolution failed while the explicit IP accepted TCP.", "Inspect the source resolver configuration and compare the same name on the router.", refs, "The supplied IP may differ from the intended answer; this does not establish a tailnet-wide DNS failure.")
	}
	correlated := false
	if router == nil {
		in.Limitations = append(in.Limitations, "Router bundle is absent; forwarding and router-to-service checks are unknown.")
	} else {
		if src.IncidentID != router.IncidentID || src.Target != router.Target || src.Synthetic != router.Synthetic || src.Redaction != router.Redaction {
			return in, errors.New("bundles must share incident, target, provenance and redaction mode")
		}
		if src.Router == "" || src.Router != router.Machine {
			return in, errors.New("selected router does not match router bundle identity")
		}
		// Even overlapping wall times do not establish synchronized clocks. Widely separated windows prohibit correlation.
		gap := time.Duration(0)
		if src.End.Before(router.Start) {
			gap = router.Start.Sub(src.End)
		} else if router.End.Before(src.Start) {
			gap = src.Start.Sub(router.End)
		}
		correlated = gap <= 30*time.Second
		if gap > 0 {
			in.Limitations = append(in.Limitations, fmt.Sprintf("Collection windows do not overlap (wall-clock gap %s); cross-machine conclusions are conditional on clock accuracy and stable conditions.", gap.Round(time.Millisecond)))
		}
		if !correlated {
			add("correlation.window_gap", "warning", "inconclusive", "Collection windows are too far apart to combine path evidence.", "Repeat both collections within 30 seconds and record any known clock skew.", []string{})
		}
		rtcp := observation(*router, "tcp")
		fwd := observation(*router, "forwarding")
		rdns := observation(*router, "dns_os")
		if success(fwd) && !*fwd.Facts.Enabled {
			add("router.forwarding_disabled", "error", "established_failure", "IP forwarding is disabled on the observed Linux router for the target address family.", "Verify that this is the router used by the target route; enable forwarding through your normal change process if appropriate.", []string{ref(*router, fwd)}, "This configuration observation alone does not prove which router the source selected or exclude policy and routing problems.")
			if correlated && success(peer) && peer.Facts.Node == src.Router && probeFailure(tcp) && success(rtcp) {
				add("path.forwarding_hypothesis", "error", "supported_hypothesis", "Disabled forwarding can explain why the source cannot reach a service that the selected router can reach.", "Verify route selection, then restore forwarding on the disposable router and repeat the same probes.", []string{ref(*src, peer), ref(*src, tcp), ref(*router, fwd), ref(*router, rtcp)}, "Route selection, access policy, filtering and return routing remain unverified.")
			}
		}
		if correlated && dns.State == Failed && success(tcp) && success(rdns) && slices.Contains(rdns.Facts.Addresses, src.Target.Address) {
			add("path.source_dns_difference", "warning", "supported_hypothesis", "The router resolves the requested name to the tested IP while the source cannot resolve it.", "Compare source and router resolver paths, search domains and split-DNS configuration.", []string{ref(*src, dns), ref(*src, tcp), ref(*router, rdns)}, "This may be an intentional resolver difference; Tailscale's DNS implementation is not proven faulty.")
		}
		if rtcp.State == Failed && rtcp.Facts.TCP == "refused" {
			add("router.tcp_refused", "warning", "established_failure", "The router received a TCP refusal for the explicit destination.", "Collect listener state on the destination and inspect any explicit reject rules.", []string{ref(*router, rtcp)}, "A closed port and an active firewall rejection can both cause refusal; no listener absence or ACL denial is established.")
		}
	}
	if probeFailure(tcp) {
		add("source.tcp_unresolved", "warning", "inconclusive", "Source TCP connectivity failed; the available probes do not establish a unique root cause.", "Inspect router-to-destination evidence, route selection and destination listener state.", []string{ref(*src, tcp)}, "Forwarding, routes, filtering, return routing and service availability can cause similar symptoms.")
	}
	slices.SortStableFunc(in.Findings, func(a, b Finding) int {
		rank := map[string]int{"error": 0, "warning": 1, "info": 2}
		return rank[a.Severity] - rank[b.Severity]
	})
	return in, nil
}
