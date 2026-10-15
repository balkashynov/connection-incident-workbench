# Validation, 2026-10-14

The documented `make test && make lab` workflow passed from the actual checkout on branch `codex/tailscale-connection-workbench`. [Source hashes, image digests and check results](verification.json) identify the tested implementation. [Lab manifest](../examples/lab-run/verification.json) records the final run. These are executed results, not planned scenarios.

Environment: native Go 1.27.1 on macOS ARM64 for race-enabled tests and vet; Docker Linux ARM64 for real Tailscale v1.104.1 clients/daemons, the same-version local DERP relay, Headscale 0.29.5 and an isolated HTTP/TCP service. Source and router occupy separate container network namespaces. Both share a transit bridge; only the router joins the service bridge. This is a single-host local lab, not separate physical networks or the Tailscale SaaS control plane.

## Executed checks

| Scenario | Observations | Observed / other states | Collection duration | Finding rules |
| --- | ---: | --- | --- | --- |
| H1 | 12 | 8 / 4 | source 0.002s, router 0.002s | source.tcp_connected |
| R1 | 12 | 7 / 5 | source 2.008s, router 0.003s | router.forwarding_disabled, path.forwarding_hypothesis, source.tcp_unresolved |
| R1-recovered | 12 | 8 / 4 | source 0.003s, router 0.002s | source.tcp_connected |
| D1 | 12 | 7 / 5 | source 0.002s, router 0.002s | source.dns_failure, path.source_dns_difference, source.tcp_connected |
| D1-recovered | 12 | 8 / 4 | source 0.002s, router 0.001s | source.tcp_connected |
| S1 | 12 | 6 / 6 | source 0.002s, router 0.002s | router.tcp_refused, source.tcp_unresolved |
| S1-recovered | 12 | 8 / 4 | source 0.002s, router 0.002s | source.tcp_connected |

Seven main runs collected **84 observations**. The real unprivileged P1 run collected **6 more**: LocalAPI DNS was denied while OS resolution and TCP remained successful. Total: **90 observations in 15 bundles**. A not-collected or failed optional diagnostic is included in “other states”; this is not a count of failed connections. The lab name is supplied through `/etc/hosts`, so the Tailscale QueryDNS endpoint does not resolve it. The report preserves that result separately from successful OS resolution.

- **H1:** source TCP and router TCP succeeded. An actual TSMP response separately established the encrypted peer data path during setup.
- **R1:** source peer ping succeeded and source TCP failed; router forwarding was false and router TCP succeeded. The configuration failure and conditional forwarding hypothesis were emitted. Restoring forwarding restored source TCP.
- **D1:** removing only the source's lab hosts entry caused OS lookup failure while explicit-IP TCP and router name resolution succeeded. Restoring the entry removed the DNS finding.
- **S1:** closing the service listener without stopping its container caused TCP refusals; restoring it restored source TCP. The analyzer reports refusal without claiming that listener absence or an ACL denial is established by the collected evidence.
- **U1:** re-analyzing real R1 source evidence without the router bundle removed the forwarding hypothesis and retained an inconclusive TCP result.
- **P1:** real unprivileged LocalAPI DNS denial preserved successful independent host probes. Unit adapter tests also inject 403s for all API reads and verify that raw errors do not leak.
- **T1:** a fixture with distant windows disables cross-machine hypotheses. Stale and mismatched identity/target/provenance controls pass.
- **X1:** exports from all seven real incidents preserved findings and cross-bundle identifiers while omitting originals. Static checks passed for 14 HTML reports: evidence anchors resolve, no scripts or external resource attributes. Malicious-text escaping is tested.

Output exclusivity, 0600 permissions, refusal to follow output symlinks, partial-output cleanup, malformed imports and oversized inputs are covered by tests. Race tests and `go vet ./...` pass.

## Browse the saved evidence

- [Forwarding failure report](../examples/lab-run/R1/incident.html), [shareable export](../examples/lab-run/R1/export.html), [raw observations and findings](../examples/lab-run/R1/incident.json).
- [Healthy control](../examples/lab-run/H1/incident.html), [forwarding recovery](../examples/lab-run/R1-recovered/incident.html).
- [DNS discrepancy](../examples/lab-run/D1/incident.html), [TCP refusal](../examples/lab-run/S1/incident.html).

The saved HTML was subsequently regenerated with report QA fixes. [The report QA record](REPORT-QA.md) contains the completed static/offline visual checks, new source hashes and representative images. Browser interaction, assistive-technology testing and a video demo remain unverified because the automated browser policy blocked local `file:` preview. The original source hashes above still identify the original live lab run.

## Reproduction and boundaries

`make lab` builds binaries and a short-lived local relay certificate, then runs `lab/run.py`. The script contains exact setup, fault, restoration and cleanup commands. It verifies the relay endpoint, route approval/acceptance, observed forwarding settings and baseline TCP before accepting failures. Forwarding changes recreate only the lab router with its state volume retained; a peer-readiness check handles reconnection before collecting evidence. Unique Compose project names scope cleanup. All final-run containers, networks and volumes were removed. No credentials or raw daemon state are in saved artifacts.

During harness development, the initial local relay certificate lacked a SAN, causing relay startup failure and unstable encrypted connectivity. The collector correctly reported failed TCP as inconclusive. The harness now generates a SAN certificate and verifies relay readiness. A subsequent router-recreation run lacked peer readiness; adding an explicit check fixed the fixture. These setup failures were not counted as passing fault scenarios, and no diagnostic rule was weakened to make them pass.

Remaining release evidence: separate-host/network testing, a dedicated Tailscale tailnet, real macOS Tailscale daemon integration, IPv6 topology behavior, browser interaction/accessibility QA, operator walkthrough and supported-version matrix. No performance, production-readiness or upstream acceptance claim is made.

The proposed next integration stage is specified in [the separate-host and dedicated-tailnet setup guide](LIVE-TEST-SETUP.md). No resources have been provisioned for that stage.
