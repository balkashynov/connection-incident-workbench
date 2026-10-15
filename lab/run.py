#!/usr/bin/env python3
"""Disposable local fault experiments. Credentials are captured in memory and never written to results."""
import concurrent.futures
import datetime
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
RUN_ID = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S%f')
PROJECT = 'tcw-lab-' + RUN_ID
COMPOSE = ['docker', 'compose', '-p', PROJECT, '-f', str(ROOT / 'lab/compose.yaml')]
OUT = ROOT / 'lab/results' / RUN_ID
OUT.mkdir(parents=True, exist_ok=False)
BIN = str(ROOT / 'bin/connection-workbench')

def cmd(args, *, env=None, secret=False, timeout=60):
    p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
    if p.returncode:
        if secret:
            raise RuntimeError('Lab registration failed; credentials omitted')
        raise RuntimeError(f'{args[:7]} failed: {p.stderr[:1200]} {p.stdout[:1200]}')
    return p.stdout.strip()

def dc(*args, **kw): return cmd(COMPOSE + list(args), **kw)
def ex(service, *args, **kw): return dc('exec', '-T', service, *args, **kw)
def ts(service, *args, **kw): return ex(service, 'tailscale', '--socket=/tmp/tailscaled.sock', *args, **kw)

def wait_ready(service):
    for _ in range(40):
        try:
            if json.loads(ts(service, 'status', '--json')).get('BackendState') == 'Running':
                return
        except (RuntimeError, json.JSONDecodeError):
            pass
        time.sleep(.5)
    raise RuntimeError(f'{service} did not become ready')

def setup():
    dc('up', '-d')
    for attempt in range(20):
        try:
            ex('derp','wget','-qO-','--no-check-certificate','https://derp/derp/probe')
            break
        except RuntimeError:
            if attempt==19: raise RuntimeError('Local relay is not ready: '+dc('logs','--tail','10','derp'))
            time.sleep(.25)
    for attempt in range(30):
        try:
            users = json.loads(ex('control', 'headscale', 'users', 'list', '-o', 'json')) or []
            break
        except RuntimeError:
            if attempt == 29: raise
            time.sleep(.5)
    user = next((u for u in users if u['name'] == 'lab'), None)
    if not user:
        ex('control', 'headscale', 'users', 'create', 'lab')
        user = next(u for u in json.loads(ex('control', 'headscale', 'users', 'list', '-o', 'json')) if u['name'] == 'lab')
    key = json.loads(ex('control', 'headscale', 'preauthkeys', 'create', '--user', str(user['id']), '--reusable', '--expiration', '1h', '-o', 'json', secret=True))['key']
    for service in ['router', 'source']:
        flags = ['--advertise-routes=172.30.96.0/24'] if service == 'router' else ['--accept-routes']
        ts(service, 'up', '--login-server=http://control:8080', '--authkey='+key, '--accept-dns=false', '--hostname='+service, '--timeout=25s', *flags, secret=True)
        wait_ready(service)
    del key
    nodes = json.loads(ex('control','headscale','nodes','list','-o','json'))
    print('Lab node route state: '+json.dumps([{k:n.get(k) for k in ['id','given_name','name','approved_routes','available_routes','subnet_routes']} for n in nodes]), flush=True)
    for node in nodes:
        if node.get('given_name') == 'router' or node.get('name') == 'router':
            ex('control','headscale','nodes','approve-routes','--identifier',str(node['id']),'--routes','172.30.96.0/24')
    time.sleep(2)
    print('Source routes: '+ex('source','ip','route','show','table','52'), flush=True)
    return ts('router', 'ip', '-4').splitlines()[0]

def collect(name, router):
    dest = OUT / name
    dest.mkdir()
    def one(role):
        remote = f'/tmp/{name}-{role}.json'
        args = ['/workbench', 'collect', '--role', role, '--incident', name,
                '--target', 'db.lab:8080', '--address', '172.30.96.10',
                '--socket', '/tmp/tailscaled.sock', '--timeout', '2s', '--out', remote]
        if role == 'source': args += ['--router', router]
        ex(role, *args)
        dc('cp', f'{role}:{remote}', str(dest / f'{role}.json'))
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        list(pool.map(one, ['source','router']))
    cmd([BIN, 'analyze', '--source', str(dest/'source.json'), '--router', str(dest/'router.json'), '--out', str(dest/'incident.json')])
    cmd([BIN, 'report', '--input', str(dest/'incident.json'), '--out', str(dest/'incident.html')])
    cmd([BIN, 'export', '--input', str(dest/'incident.json'), '--out', str(dest/'export.json')])
    cmd([BIN, 'report', '--input', str(dest/'export.json'), '--out', str(dest/'export.html')])
    inx = json.loads((dest/'incident.json').read_text())
    summary = {'scenario':name, 'rules':[f['rule_id'] for f in inx['findings']], 'probes':{b['role']:{o['kind']:{'state':o['state'],'facts':o['facts']} for o in b['observations']} for b in inx['bundles']}, 'observations':sum(len(b['observations']) for b in inx['bundles'])}
    print(json.dumps({'scenario':name,'rules':summary['rules']}), flush=True)
    return summary

def require(result, *rules):
    for rule in rules:
        assert rule in result['rules'], (result['scenario'], 'missing', rule, result['probes'])

def forwarding(value):
    env = dict(os.environ, TCW_FORWARDING=str(value))
    dc('up', '-d', 'router', env=env)
    wait_ready('router')
    actual = ex('router','cat','/proc/sys/net/ipv4/ip_forward')
    assert actual == str(value), ('forwarding',actual,value)
    ts('source','ping','--c=5','--timeout=5s',ts('router','ip','-4').splitlines()[0])

results=[]
try:
    router = setup()
    # Warm the selected peer; no application conclusion is drawn from this ping.
    ts('source','ping','--c=3','--timeout=3s',router)
    try:
        print('TSMP data-path check: '+ts('source','ping','--tsmp','--c=2','--timeout=5s',router),flush=True)
    except RuntimeError:
        for role in ['source','router']:
            logs=dc('logs','--tail','70',role)
            print('Lab daemon diagnostics '+role+':\n'+'\n'.join(line for line in logs.splitlines() if any(word in line.lower() for word in ['drop','handshake','wireguard','error','filter','endpoint'])),flush=True)
        raise
    results.append(collect('H1',router))
    if 'source.tcp_connected' not in results[-1]['rules']:
        for role in ['source','router']:
            netmap=json.loads(ts(role,'debug','netmap'))
            print(role+' packet filter: '+json.dumps({k:v for k,v in netmap.items() if 'filter' in k.lower()}),flush=True)
            print(role+' IP selection: '+ex(role,'ip','route','get','172.30.96.10'),flush=True)
            for args in [('ip','route','show','table','all'),('ip','rule'),('iptables','-nvL'),('iptables','-t','nat','-nvL'),('sysctl','net.ipv4.conf.all.rp_filter')]:
                print(role+' '+str(args)+': '+ex(role,*args),flush=True)
    require(results[-1], 'source.tcp_connected')
    assert results[-1]['probes']['router']['tcp']['facts']['tcp']=='connected'
    forwarding(0)
    results.append(collect('R1',router));require(results[-1], 'router.forwarding_disabled','path.forwarding_hypothesis','source.tcp_unresolved')
    r1=OUT/'R1'
    cmd([BIN,'analyze','--source',str(r1/'source.json'),'--out',str(r1/'missing-router.json')])
    missing=json.loads((r1/'missing-router.json').read_text())
    assert 'path.forwarding_hypothesis' not in [f['rule_id'] for f in missing['findings']]
    forwarding(1)
    results.append(collect('R1-recovered',router));require(results[-1],'source.tcp_connected')
    ex('source','sh','-c',"cp /etc/hosts /tmp/hosts.backup; sed '/db.lab/d' /etc/hosts > /tmp/hosts.no-db; cat /tmp/hosts.no-db > /etc/hosts")
    results.append(collect('D1',router));require(results[-1],'source.dns_failure','path.source_dns_difference','source.tcp_connected')
    ex('source','sh','-c','cat /tmp/hosts.backup > /etc/hosts')
    results.append(collect('D1-recovered',router));require(results[-1],'source.tcp_connected')
    assert 'source.dns_failure' not in results[-1]['rules']
    dc('kill','-s','SIGUSR2','service');time.sleep(.5)
    results.append(collect('S1',router));require(results[-1],'router.tcp_refused','source.tcp_unresolved')
    dc('kill','-s','SIGUSR2','service');time.sleep(.5)
    results.append(collect('S1-recovered',router));require(results[-1],'source.tcp_connected')
    # A real unprivileged local-socket denial, while host probes still work.
    remote='/tmp/P1.json'
    dc('exec','-T','--user','65534:65534','source','/workbench','collect','--role','source','--incident','P1','--target','db.lab:8080','--address','172.30.96.10','--router',router,'--socket','/tmp/tailscaled.sock','--out',remote)
    dc('cp',f'source:{remote}',str(OUT/'P1-source.json'))
    p1=json.loads((OUT/'P1-source.json').read_text())
    assert next(o for o in p1['observations'] if o['kind']=='tcp')['state']=='observed'
    denied=[o['kind'] for o in p1['observations'] if o['state']=='permission_denied']
    # Some read endpoints are permitted to unprivileged users. Record actual behavior.
    results.append({'scenario':'P1','denied_probes':denied,'observations':len(p1['observations'])})
    manifest={'status':'passed','environment':'Docker Linux ARM64 on one macOS host; Headscale 0.29.5; Tailscale client/daemon/relay 1.104.1','limits':['Not Tailscale SaaS','Not separate physical networks','Not macOS Tailscale daemon integration','No application protocol checks or destination listener evidence'], 'results':results}
    (OUT/'verification.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Verified results: '+str(OUT),flush=True)
finally:
    # This project name is reserved for this disposable lab. Never prune global Docker resources.
    dc('down','-v','--remove-orphans')
