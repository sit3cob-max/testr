#!/usr/bin/env python3
import argparse,html,json
from pathlib import Path
from collections import Counter
def e(x):return html.escape(str(x),quote=True)
def code_block(block):
 before=[];after=[]
 for r in block:
  if r['kind']=='deleted':before.append(f"{r.get('old') or '' :>4}  - {e(r.get('before',''))}")
  elif r['kind']=='added':after.append(f"{r.get('new') or '' :>4}  + {e(r.get('after',''))}")
  else:
   before.append(f"{r.get('old') or '' :>4}    {e(r.get('before',''))}");after.append(f"{r.get('new') or '' :>4}    {e(r.get('after',''))}")
 return '\n'.join(before), '\n'.join(after)
def main():
 p=argparse.ArgumentParser();p.add_argument('--input');p.add_argument('--output');a=p.parse_args();d=json.loads(Path(a.input).read_text(encoding='utf-8'));counts=d['counts'];cats=Counter(q['category'] for f in d['files'] for q in f['findings']);maxc=max(cats.values() or [1]);bars=''.join(f'<div class=bar><span>{e(k)}</span><i><b style="width:{v/maxc*100:.1f}%"></b></i><strong>{v}</strong></div>' for k,v in cats.items()) or '<p class=ok>No issues</p>';cards=[]
 for f in d['files']:
  issues=[]
  for q in f['findings']:
   before,after=code_block(q['block']);diff=(f'<div class=compare><div><label>Before</label><pre>{before or "New file"}</pre></div><div><label>After</label><pre>{after}</pre></div></div>') if before else f'<div class=single><label>Code</label><pre>{after}</pre></div>'
   issues.append(f'''<details class="issue {q['severity'].lower()}"><summary><span class=badge>{e(q['severity'])}</span><b>{e(q['rule'])}</b><span>{e(q['issue'])}</span><em>Line {q['line']}</em></summary><div class=body><div class=words><p><strong>Why:</strong> {e(q['why'])}</p><p><strong>Fix:</strong> {e(q['fix'])}</p></div>{diff}</div></details>''')
  cards.append(f'<section class=file><header><h2>{e(f["path"])}</h2><span>{len(f["findings"])} issue(s)</span></header>{"".join(issues)}</section>')
 sev=''.join(f'<div class="sev {s.lower()}"><span>{s.title()}</span><b>{counts.get(s,0)}</b><i style="height:{max(3,counts.get(s,0)*22)}px"></i></div>' for s in ['CRITICAL','HIGH','MEDIUM','LOW']);doc=f'''<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Compliance Dashboard</title><link rel=stylesheet href="assets/dashboard.css"></head><body><main><header class=top><div><h1>Compliance Dashboard</h1><p>MISRA + AUTOSAR changed code</p></div><div>Build {e(d['build'])} · {e(d['commit'])}</div></header><section class="result {d['status'].lower()}"><div><b>{e(d['status'])}</b><small>{e(d['gate'])}</small></div><strong>{d['score']}%</strong></section><section class=kpis><div><span>Issue files</span><b>{len(d['files'])}</b></div><div><span>Issues</span><b>{d['total']}</b></div><div><span>Critical</span><b>{counts.get('CRITICAL',0)}</b></div><div><span>High</span><b>{counts.get('HIGH',0)}</b></div></section><section class=charts><article><h2>Issues by type</h2>{bars}</article><article><h2>Severity</h2><div class=sevchart>{sev}</div></article></section>{''.join(cards) if cards else '<div class=empty><b>No issues found</b><p>Changed code passed the checks.</p></div>'}<footer>Only files and code blocks with issues are shown.</footer></main></body></html>''';o=Path(a.output);o.parent.mkdir(parents=True,exist_ok=True);o.write_text(doc,encoding='utf-8')
if __name__=='__main__':main()
