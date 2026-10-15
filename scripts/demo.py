#!/usr/bin/env python3
"""Replay collected lab evidence without running any network probes."""
import json
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
cli = root / "bin/connection-workbench"
saved = root / "examples/lab-run"
output_root = root / "demo-output"
output_root.mkdir(exist_ok=True)
out = Path(tempfile.mkdtemp(prefix="replay-", dir=output_root))


def run(*args):
    subprocess.run([str(cli), *map(str, args)], check=True)


cases = [
    ("01-healthy", "H1", True),
    ("02-source-only", "R1", False),
    ("03-paired", "R1", True),
    ("04-recovered", "R1-recovered", True),
]
rules = {}
for name, scenario, paired in cases:
    path = out / (name + ".json")
    args = ["analyze", "--source", saved / scenario / "source.json", "--out", path]
    if paired:
        args += ["--router", saved / scenario / "router.json"]
    run(*args)
    run("report", "--input", path, "--out", out / (name + ".html"))
    rules[name] = [f["rule_id"] for f in json.loads(path.read_text())["findings"]]

run("export", "--input", out / "03-paired.json", "--out", out / "05-shareable.json")
run("report", "--input", out / "05-shareable.json", "--out", out / "05-shareable.html")
rules["05-shareable"] = [
    f["rule_id"] for f in json.loads((out / "05-shareable.json").read_text())["findings"]
]

assert rules["01-healthy"] == ["source.tcp_connected"]
assert rules["02-source-only"] == ["source.tcp_unresolved"]
assert "path.forwarding_hypothesis" in rules["03-paired"]
assert rules["04-recovered"] == ["source.tcp_connected"]
assert rules["05-shareable"] == rules["03-paired"]

print("Replayed saved, collected evidence. No new probes or live-network test ran.")
for name in rules:
    print(f"{name}: {', '.join(rules[name])}")
print(f"Open the numbered HTML reports in: {out}")
