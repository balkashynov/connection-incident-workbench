#!/usr/bin/env python3
"""Render saved evidence and a clearly synthetic long-identifier control to HTML."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
cli = root / "bin/connection-workbench"
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=False)
cases = {
    "forwarding": "R1/incident.json", "healthy": "H1/incident.json",
    "dns": "D1/incident.json", "refused": "S1/incident.json",
    "redacted": "R1/export.json", "missing": "R1/missing-router.json",
}

def report(source, name):
    subprocess.run([str(cli), "report", "--input", str(source),
                    "--out", str(out / (name + ".html"))], check=True)

for name, source in cases.items():
    report(root / "examples/lab-run" / source, name)
subprocess.run([str(cli), "analyze", "--source", str(root / "examples/lab-run/P1-source.json"),
                "--out", str(out / "denied.json")], check=True)
report(out / "denied.json", "denied")
stress = json.loads((root / "examples/lab-run/R1/incident.json").read_text())
for bundle in stress["bundles"]:
    bundle["synthetic"] = True
    bundle["incident_id"] = "i" * 128
    bundle["bundle_id"] = bundle["role"][0] * 128
    bundle["target"]["host"] = "host." + "long" * 60
    for observation in bundle["observations"]:
        observation["id"] = observation["kind"] + "-long-" + "x" * 90
(out / "stress.json").write_text(json.dumps(stress))
report(out / "stress.json", "stress")
