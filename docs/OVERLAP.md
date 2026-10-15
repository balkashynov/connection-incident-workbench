# Overlap check, 2026-10-14

Inspected fresh public source, README roadmaps and open issue lists. These are source comparisons, not runtime benchmarks of competing tools.

| Project | Inspected revision | Relevant behavior | Increment beyond it |
| --- | --- | --- | --- |
| [Taildoctor](https://github.com/jjhfarmer/taildoctor) | `21a3c7051426945cfe52d5e8162448c8546bee3b` | Apache-2.0; local daemon readiness, network readiness, self-name DNS. `internal/check/{check,dns,network}.go`. Peer checks, support bundles and JSON are roadmap items. | Correlate two explicitly collected machine bundles for the same destination, with evidence references and offline export. |
| [TailTunnel](https://github.com/rajsinghtech/tailtunnel) | `eeab20fe01139657fcc4b75f3991ef09e6fb2def` | MIT; browser SSH, peer disco pings and monitoring. `internal/canary/pinger.go`, `internal/diagnostics/diagnostics.go`, API routes. | Explain the gap between successful diagnostic peer ping and failed destination TCP using router observations. |
| [Tailscale](https://github.com/tailscale/tailscale/releases/tag/v1.104.1) | release `v1.104.1` | Existing LocalAPI adapter and DERP relay. | Reuse both; no new ping or relay implementation. |

Taildoctor's open [issue #13](https://github.com/jjhfarmer/taildoctor/issues/13) proposes comparing userspace and daemon network observations. That execution-context comparison is useful but distinct from our source/router evidence. No matching two-machine destination incident correlator appeared in the inspected code/roadmap. This is not proof of absence in private or future work.

Three discriminating cases:

1. Source DNS fails, source explicit-IP TCP works, router resolves the same name to that IP. Compare resolver contexts without claiming a tailnet-wide outage.
2. Source reaches selected peer but service TCP fails; router forwarding is disabled and its direct service TCP works. Identify an observed configuration failure and a conditional explanation of the source symptom.
3. Router TCP is refused; source TCP also fails. Preserve refusal evidence without claiming an absent listener or ACL denial. Require destination evidence to distinguish those explanations.

Decision: independent companion prototype with a portable schema. Taildoctor's models live under `internal/check` and focus on local diagnostic areas, so they are not a reusable public library. No competing implementation has been copied. An evidence adapter or extension remains a plausible future collaboration path, subject to maintainer interest; no acceptance or outreach is claimed.

Module: `tailscale.com v1.104.1`, requiring Go 1.27.1. Status, disco ping and QueryDNS stay behind allowlisted facts. LocalAPI compatibility outside tested client/daemon versions is unverified.
