"""Run inside the isolated rendering container; fail on horizontal text overflow."""
import json
from pathlib import Path
import subprocess
import sys

results = []
for source in sorted(Path("/input").glob("*.html")):
    for width in [1280, 390, 320]:
        out = Path("/out") / (source.stem + "-" + str(width) + ".pdf")
        subprocess.run([sys.executable, "/renderer/render.py", str(source), str(out),
                        str(width), "16000"], check=True)
        data = json.loads(Path(str(out) + ".json").read_text())
        overflow = [box for box in data["text_boxes"]
                    if box["x"] < -0.5 or box["x"] + box["width"] > width + 0.5]
        assert not overflow, (out.name, overflow)
        overlaps = []
        for i, a in enumerate(data["blocks"]):
            for b in data["blocks"][i+1:]:
                if (min(a["x"] + a["width"], b["x"] + b["width"]) > max(a["x"], b["x"]) + 0.5
                        and min(a["y"] + a["height"], b["y"] + b["height"]) > max(a["y"], b["y"]) + 0.5):
                    overlaps.append((a, b))
        assert not overlaps, (out.name, overlaps)
        results.append({"case": source.stem, "width": width,
                        "overflow_text_boxes": len(overflow),
                        "overlapping_cards_or_headings": len(overlaps),
                        "asset_fetch_attempts": len(data["network_attempts"])})
        print(out.name + ": passed", flush=True)
assert len(results) == 24, "Expected eight cases at three widths"
Path("/out/results.json").write_text(json.dumps(results, indent=2) + "\n")
