#!/usr/bin/env python3
"""Static, non-executing checks for saved lab incidents and their shareable exports."""
from html.parser import HTMLParser
from pathlib import Path
import json
import sys
from urllib.parse import unquote

class Report(HTMLParser):
    def __init__(self):
        super().__init__();self.ids=set();self.refs=[];self.external=[];self.scripts=0;self.duplicate_ids=[];self.captions=0;self.tables=0;self.headers=0;self.language=None;self.main=0;self.events=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='script':self.scripts+=1
        if 'id' in a:
            if a['id'] in self.ids:self.duplicate_ids.append(a['id'])
            self.ids.add(a['id'])
        self.events.extend(key for key in a if key.startswith('on'))
        if tag=='html':self.language=a.get('lang')
        if tag=='main':self.main+=1
        if tag=='table':self.tables+=1
        if tag=='caption':self.captions+=1
        if tag=='th':
            assert a.get('scope')=='col'
            self.headers+=1
        if 'href' in a:
            if a['href'].startswith('#'):self.refs.append(unquote(a['href'][1:]))
            else:self.external.append(a['href'])
        for key in ['src','action']:
            if key in a:self.external.append(a[key])

root=Path(sys.argv[1]);cases=0;reports=0
for path in sorted(root.glob('*/incident.json')):
    incident=json.loads(path.read_text())
    export_text=(path.parent/'export.json').read_text()
    export=json.loads(export_text)
    assert [f['rule_id'] for f in incident['findings']]==[f['rule_id'] for f in export['findings']]
    for bundle in incident['bundles']:
        for value in [bundle['incident_id'],bundle['bundle_id'],bundle['machine'],bundle['target']['host'],bundle['target']['address'],bundle.get('selected_router')]:
            if value:assert json.dumps(value) not in export_text, ('identifier leak',path,value)
    a,b=export['bundles'];assert a['selected_router']==b['machine'] and a['target']==b['target']
    for inx in [incident,export]:
        refs={b['bundle_id']+'/'+o['id'] for b in inx['bundles'] for o in b['observations']}
        for finding in inx['findings']:assert set(finding['evidence'])<=refs
    for html in path.parent.glob('*.html'):
        check=Report();check.feed(html.read_text())
        assert not check.scripts and not check.external and not check.events, html
        assert not check.duplicate_ids and set(check.refs)<=check.ids, html
        assert check.language=='en' and check.main==1, html
        assert check.tables==check.captions==len(incident['bundles']), html
        assert check.headers==4*check.tables, html
        assert {'findings','ledger','coverage'}<=check.ids, html
        reports+=1
    cases+=1
assert cases>=1
print(json.dumps({'incidents':cases,'html_reports':reports,'checks':['export identifiers omitted','cross-bundle correlation preserved','finding rules preserved','evidence references resolve','no scripts, event handlers or external resource attributes','unique anchors','language and main landmark','captioned tables with scoped headers']}))
