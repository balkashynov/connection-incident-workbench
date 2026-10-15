#!/usr/bin/env python3
"""Build the collector and upstream DERP relay for the Docker server's architecture."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent.parent

def run(args, **kwargs): return subprocess.check_output(args, text=True, **kwargs).strip()
arch = run(['docker','info','--format','{{.Architecture}}'])
arch = {'aarch64':'arm64','x86_64':'amd64'}.get(arch,arch)
if arch not in ['arm64','amd64']: raise SystemExit('Unsupported lab architecture: '+arch)
env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH=arch)
(root/'bin').mkdir(exist_ok=True)
subprocess.run(['go','build','-trimpath','-o',str(root/'bin/connection-workbench-linux'),'./cmd/connection-workbench'],cwd=root,env=env,check=True)
run(['go','mod','download','tailscale.com'],cwd=root)
cache = Path(run(['go','env','GOMODCACHE'],cwd=root))/'tailscale.com@v1.104.1'
subprocess.run(['go','build','-mod=readonly','-trimpath','-o',str(root/'bin/derper'),'./cmd/derper'],cwd=cache,env=env,check=True)
certs=root/'lab/certs';certs.mkdir(exist_ok=True)
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(certs/'derp.key'),'-out',str(certs/'derp.crt'),'-days','2','-subj','/CN=derp','-addext','subjectAltName=DNS:derp'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
os.chmod(certs/'derp.key',0o600)
