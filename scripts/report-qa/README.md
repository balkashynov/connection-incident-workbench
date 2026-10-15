# Offline report layout checks

This optional QA tool uses WeasyPrint 66.0, a paged HTML/CSS renderer without a JavaScript engine. It is not a browser or a substitute for browser interaction, keyboard or assistive-technology testing. It never serves the reports. Runtime networking is disabled and the renderer rejects every asset fetch. The report's single width media query is selected explicitly because WeasyPrint does not implement viewport-width queries. Print media rules are excluded from this screen-layout approximation.

From the repository root, after `make build`:

```sh
qa_dir=$(mktemp -d /tmp/tcw-report-qa.XXXXXX)
python3 scripts/report-qa/prepare.py "$qa_dir/input"
mkdir "$qa_dir/output"
docker build -t tcw-report-qa:local scripts/report-qa
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp \
  -e XDG_CACHE_HOME=/tmp/fontcache \
  -v "$PWD/scripts/report-qa:/renderer:ro" \
  -v "$qa_dir/input:/input:ro" -v "$qa_dir/output:/out" \
  tcw-report-qa:local /renderer/batch.py
```

The build downloads pinned WeasyPrint and OS dependencies; runtime rendering is offline. Eight variants at 1280, 390 and 320 CSS pixels must contain no horizontally overflowing text boxes, overlapping finding cards/section headings or asset fetch attempts. The 16000-pixel canvas prevents pagination during the check. JSON metrics accompany each PDF; `results.json` is written only after all 24 pass. `prepare.py` uses saved real evidence except the explicitly synthetic long-identifier case. No network probes are run.

Rasterize selected PDFs with `pdftoppm -f 1 -singlefile -scale-to-x 390 -scale-to-y -1 -png input.pdf output` (use the original width). Inspect the path summary, complete finding cards, ledger and footer. Text-bound checks alone do not detect every overlap or rendering issue. The renderer's private box-tree API is confined to this pinned QA tool, not used by the CLI.

Generated files stay outside the checkout. The dated QA record links representative crops and records the actual tested source hashes. A desktop browser pass remains a separate, explicitly recorded check.
