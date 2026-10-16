#!/usr/bin/env python3
"""Build the public browser demo from saved lab bundles using the real CLI."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SAVED = ROOT / "examples/lab-run"
OUT = ROOT / "docs/demo"
CLI = ROOT / "bin/connection-workbench"
CASES = [("healthy", "H1", True), ("source-only", "R1", False),
         ("paired", "R1", True), ("recovered", "R1-recovered", True)]


def run(*args):
    subprocess.run([str(CLI), *map(str, args)], check=True)


with tempfile.TemporaryDirectory(prefix="connection-demo-") as tmp:
    stage = Path(tmp)
    rules = {}
    for name, scenario, paired in CASES:
        path = stage / f"{name}.json"
        args = ["analyze", "--source", SAVED / scenario / "source.json", "--out", path]
        if paired:
            args += ["--router", SAVED / scenario / "router.json"]
        run(*args)
        run("report", "--input", path, "--out", stage / f"{name}.html")
        rules[name] = [f["rule_id"] for f in json.loads(path.read_text())["findings"]]
    run("export", "--input", stage / "paired.json", "--out", stage / "shareable.json")
    run("report", "--input", stage / "shareable.json", "--out", stage / "shareable.html")
    rules["shareable"] = [f["rule_id"] for f in json.loads((stage / "shareable.json").read_text())["findings"]]
    assert rules["healthy"] == ["source.tcp_connected"]
    assert rules["source-only"] == ["source.tcp_unresolved"]
    assert "path.forwarding_hypothesis" in rules["paired"]
    assert rules["recovered"] == ["source.tcp_connected"]
    assert rules["shareable"] == rules["paired"]
    OUT.mkdir(exist_ok=True)
    manifest = {"provenance": "Saved real-daemon lab observations, analyzed by the CLI. No new network probes.",
                "rules": rules, "sha256": {}}
    for path in sorted(stage.iterdir()):
        data = path.read_bytes()
        (OUT / path.name).write_bytes(data)
        manifest["sha256"][path.name] = hashlib.sha256(data).hexdigest()
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("Built five browser demo cases from the saved lab evidence.")
