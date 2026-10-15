# Evidence contract v1

`collect` emits a bundle. Required fields are enforced by `Bundle.Validate` in `internal/workbench/evidence.go`. `analyze` emits an incident containing one source and optionally one router bundle, findings and interpretation limitations. Schema version is integer `1`; other versions are rejected. Tool version and pinned LocalAPI-client version are recorded separately from the observed daemon version.

The endpoint contract requires an OS lookup name, explicit destination IP and TCP port. Both bundles must match all three, the incident ID, redaction mode and synthetic/collected provenance. The source's explicitly selected router must equal the router's observed Tailscale identity. A disco ping's responding node must also match before it can support the forwarding hypothesis. The target equality check preserves endpoint correlation without inferring that a DNS answer matched the supplied IP.

Each observation has an ID unique within its bundle, an allowlisted kind/method, a state, wall-clock start/end, a monotonic duration in milliseconds, typed facts and a sanitized error code. Finding references use `bundle_id/observation_id`. States are `observed`, `failed`, `permission_denied`, `unsupported`, `timed_out`, `stale`, `not_collected`. The collector records explicit missing/unsupported probes; external stale evidence can be represented without retaining affirmative facts. Absolute age is not automatically interpreted: saved reports describe their collection window, never current health.

Allowlisted methods:

| Kind | Method | Facts |
| --- | --- | --- |
| daemon | localapi.status | Backend, daemon version, this node's Tailscale identity |
| dns_os | os.lookup_ip | Resolved IPs for the requested name |
| dns_tailscale | localapi.query_dns | A or AAAA answers, selected by the explicit target family |
| peer | localapi.ping.disco | Responding node and direct/DERP/peer-relay/unknown path classification |
| tcp | os.tcp_dial | Connected, refused, timeout or failed |
| forwarding | linux.proc_sys | Boolean for the target family's forwarding setting |

No arbitrary API objects or error strings are accepted. Unsupported major versions, unknown fields, duplicate observation kinds/IDs, impossible windows, misplaced facts and oversized imports are rejected. Findings from imported incident JSON are **not trusted**: analysis and report generation recompute them from the validated bundles. A bundle can be forged; validation establishes shape, not authenticity.

Rules are pure and deterministic for the supplied evidence. Each has an explicit version and category. `established_failure` refers to an observed failure such as disabled forwarding or a TCP refusal, not automatically the root cause of the source symptom. Cross-machine findings remain hypotheses. A greater-than-30-second gap between collection windows blocks those hypotheses; any non-overlap is disclosed. Overlapping timestamps do not establish synchronized clocks.

Export first validates the combined incident, then uses one shared map for machine/router/name/IP identifiers, replaces arbitrary incident and observation IDs, omits daemon/client version detail and re-runs analysis. No reverse map or salt is saved. The exported incident remains analyzable but cannot be used for collection. Independently redacted source/router bundles are not a supported input workflow. Timing, platform, ports and topology remain visible. A privacy review before external sharing is still required.

The HTML renderer uses Go `html/template` for escaping, a restrictive no-network/no-script CSP and static evidence anchors. No imported text becomes executable markup, script or shell commands.
