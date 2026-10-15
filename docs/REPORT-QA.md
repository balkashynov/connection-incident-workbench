# Report QA, 2026-10-14

The static and offline visual pass is complete. Actual browser interaction and assistive-technology checks remain pending. The earlier browser security policy blocked local `file:` preview; this pass did not serve the report or use another browser surface to bypass that restriction.

## Fixes

- The path summary now displays the saved forwarding result and router TCP outcome. Missing, stale and denied evidence stays explicit; bundle order does not affect the summary.
- Evidence links use short role/probe labels while retaining the exact observation fragment and full-reference tooltip. Findings show severity in text as well as color. States and categories have readable labels.
- The ledger stacks on narrow screens. Long identifiers wrap; cards have sufficient separation and no longer overlap the ledger in the offline renderer. Both ends of a collection window include the date.
- Added section navigation, keyboard focus styling, table captions and scoped headers. Native table roles are retained when CSS changes their narrow-screen layout.

The original 390-pixel render had 14 horizontally overflowing text boxes in the ledger. The final eight-case matrix has zero at every checked width. Visual inspection also caught overlapping finding cards/headings in an intermediate layout; an explicit overlap check now covers that failure mode.

## Executed checks

| Check | Result |
| --- | --- |
| Race-enabled Go tests and vet, native macOS ARM64 / Go 1.27.1 | Passed, including report outcome, reversed-bundle, missing/stale/denied, long-ID fragment and HTML-escaping regressions. |
| Saved examples regenerated from existing JSON | 14 HTML reports from seven incidents. No evidence JSON, collector, analysis rule or pseudonymization implementation changed. |
| Static saved-artifact checks | All fragment targets exist, IDs are unique, no script/event-handler/external-resource attributes, language/main landmark and captioned/scoped tables present. Export identifiers omitted and findings/correlation preserved. |
| Offline layout matrix | 24 passes: healthy, forwarding fault, DNS discrepancy, refusal, missing router, denied LocalAPI, redacted report and synthetic long identifiers, each at 1280, 390 and 320 CSS pixels. |
| Layout measurements | Zero horizontal text overflow, finding-card/section-heading intersections or asset fetch attempts. |
| Visual inspection | Desktop and narrow path summaries, complete finding cards, ledger transitions/rows, redaction/missing/denied variants, stress wrapping and coverage/footer inspected in rasterized output. Representative final crops linked below. |

[Machine-readable results and source/artifact hashes](qa/2026-10-14/verification.json) identify this pass. [Reproduction commands](../scripts/report-qa/README.md) generate all variants from saved evidence. The existing [lab validation](VALIDATION.md) and its `verification.json` describe the earlier runtime experiment and original report revision; they are not evidence of a new live-network run.

The renderer was WeasyPrint 66.0 on Linux ARM64 in a network-disabled, read-only container with no JavaScript engine. Every asset fetch was rejected. Its width media query was selected explicitly, and print rules were excluded. The output is a screen-layout approximation using the renderer's font/CSS implementation. Box bounds and static HTML checks are not a browser accessibility audit.

## Representative final views

- [Desktop path and findings](qa/2026-10-14/forwarding-desktop.png).
- [390-pixel ledger and finding boundary](qa/2026-10-14/forwarding-mobile-ledger.png).
- [390-pixel forwarding fact and coverage/footer](qa/2026-10-14/forwarding-mobile-end.png).
- [320-pixel long-identifier control](qa/2026-10-14/long-identifiers.png).

These are offline-rendered crops, not browser screenshots. Full temporary PDFs, rasterizations and box metrics can be recreated with the saved scripts.

## Browser/operator checks still to record

Open the saved HTML manually in a desktop browser and record browser/version, OS and report hash. At desktop and narrow width, follow a finding's evidence link and verify the intended highlighted row; use Back and the section links; expand/collapse each limits disclosure; tab through links and summaries with a visible focus indicator; inspect at 200% zoom; and confirm table labels/navigation in a screen reader. Test normal scrolling through the entire report and browser print preview if print output is intended.

No JavaScript behavior needs testing. Native link, disclosure, focus, screen-reader and browser-print behavior has not been executed in this pass. The [separate-host setup guide](LIVE-TEST-SETUP.md) describes the remaining integration stage.
