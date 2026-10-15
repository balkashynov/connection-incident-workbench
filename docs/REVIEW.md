# Demo review, 2026-10-14

## Decision

Useful enough for focused engineering feedback. There is not yet evidence for adoption into Tailscale's daemon or CLI, improved support resolution time, or production readiness.

The forwarding case demonstrates a concrete increment over a peer ping or source-only TCP check: router evidence supports a narrower explanation and next check. The missing-router control prevents the same explanation when that evidence is absent. Healthy and recovered runs bracket the injected fault. The core value is the combination of evidence, explicit uncertainty and a portable report, rather than novel individual probes.

## Review findings

- The saved forwarding report correctly distinguishes a measured configuration fact from a hypothesis about the failed source connection. Every finding references observations. Source-only analysis remains inconclusive.
- The main report repeats related conclusions across three cards. This is verbose, but the fact, hypothesis and remaining uncertainty are materially different; it is not a correctness blocker for a prototype.
- Collection and route selection are still manual. This is the main usability cost to validate with prospective users before adding more features.
- The lab's QueryDNS failure must be explained prominently. The test name is supplied through hosts files; the healthy control does not establish Tailscale DNS health. The demo now states this beside the comparison table.
- A reviewer previously had to reconstruct the comparison from individual artifacts. `make demo` now replays the healthy, source-only, paired, recovered and exported cases without a new network experiment. It produces new files and checks the expected findings.
- Export preserves identity relationships and findings. It is pseudonymization, not complete anonymization: platform, timing, ports and topology remain. Published raw example addresses/names belong only to the disposable lab.
- Public material excludes personal machine/account planning and the original local Git history. Collector, analyzer, evidence validation, redaction and report implementation are unchanged from the reviewed local source snapshot.

## Verification boundary

The earlier local runtime experiment is recorded in [VALIDATION.md](VALIDATION.md). It collected 90 observations, including the three controlled fault/recovery cases and an unprivileged LocalAPI check. Its saved artifacts were retained, not represented as a new runtime run.

The report preview was visually inspected. It is an offline-rendered image. Browser interaction, keyboard/screen-reader behavior and browser print are still unverified. No alternate browser route was used to bypass the earlier local-file policy restriction.

The fresh publication-package check results are in [review-verification.json](review-verification.json). These cover native race tests, vet, build, saved-artifact checks and replay from the curated source tree. They do not establish native macOS Tailscale daemon or separate-network operation.

## Contribution path

[Tailscale #18943](https://github.com/tailscale/tailscale/issues/18943) remains open. Its [maintainer reply](https://github.com/tailscale/tailscale/issues/18943#issuecomment-4035510053) recommends a separate prototype and community feedback. [Tailscale's contribution guidance](https://github.com/tailscale/tailscale/blob/main/.github/CONTRIBUTING.md) asks for discussion and design agreement before new functionality.

The next step is a concise comment on that existing issue with this runnable demo and a question about the usefulness of paired evidence. No upstream PR is proposed at this stage. Taildoctor and TailTunnel still overlap with local diagnostics and monitoring; their checked revisions match [OVERLAP.md](OVERLAP.md). A future extension to existing tooling is an option if maintainers see value.
