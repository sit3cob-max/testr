#!/usr/bin/env python3
"""Professional changed-code reviewer for Jenkins. Python 3.8+, stdlib only."""
import argparse, datetime as dt, hashlib, html, json, os, re, subprocess, sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

VERSION="3.0.0"
WEIGHTS={"CRITICAL":30,"HIGH":12,"MEDIUM":5,"LOW":1}
RULES=[
("SECRET","CRITICAL","Security",re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),"Hardcoded credential","A credential-like value is stored in source code.","Use Jenkins Credentials, an environment variable, or an approved secret store."),
("EVAL","HIGH","Security",re.compile(r"\beval\s*\("),"Unsafe eval usage","eval() can execute untrusted input.","Use explicit parsing or a controlled command mapping."),
("EXEC","HIGH","Security",re.compile(r"\bexec\s*\("),"Unsafe exec usage","exec() dynamically executes code.","Replace dynamic execution with explicit function dispatch."),
("SHELL","HIGH","Security",re.compile(r"shell\s*=\s*True"),"Shell injection exposure","shell=True can make command construction unsafe.","Pass arguments as a list and keep shell=False."),
("BARE","MEDIUM","Reliability",re.compile(r"except\s*:\s*$"),"Bare exception handler","A bare except can hide unexpected failures.","Catch specific exception types and log actionable context."),
("TODO","LOW","Maintainability",re.compile(r"(?i)\b(todo|fixme|temporary workaround)\b"),"Unfinished work marker","The changed line contains unfinished work.","Complete it or link it to a tracked work item."),
("DEBUG","LOW","Maintainability",re.compile(r"\bprint\s*\(|console\.log\s*\("),"Debug output","Debug output can create production log noise.","Use structured logging at the appropriate level.")]
DEFAULT={"thresholds":{"good":85,"warning":60,"max_critical":0,"max_high":5},"scan":{"extensions":[".py",".java",".js",".ts",".tsx",".jsx",".c",".cpp",".h",".hpp",".cs",".go",".rs",".sh",".ps1",".yaml",".yml",".gradle",".groovy"],"names":["Dockerfile","Jenkinsfile"],"exclude":[".git/","node_modules/","dist/","build/","target/","venv/",".venv/","__pycache__/","review-output/","jenkins/ai_code_reviewer_v1.py","jenkins/ai_code_reviewer_v2.py","jenkins/ai_code_reviewer_v3.py","ai_code_review_history.json"]},"history":{"file":"ai_code_review_history.json","max":30}}

@dataclass
class Finding: id:str; file:str; line:int; severity:str; category:str; title:str; description:str; recommendation:str; code:str
@dataclass
class Row: old:Optional[int]; new:Optional[int]; before:str; after:str; kind:str
@dataclass
class FileReview: path:str; status:str; added:int; deleted:int; rows:List[Row]; findings:List[Finding]

def cmd(c:List[str],cwd:Path)->Tuple[int,str,str]:
 p=subprocess.run(c,cwd=str(cwd),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,errors="replace"); return p.returncode,p.stdout.strip(),p.stderr.strip()
def git(w:Path,*a:str)->str:return cmd(["git",*a],w)[1]
def merge(a:Dict,b:Dict)->Dict:
 r=dict(a)
 for k,v in b.items():r[k]=merge(r[k],v) if isinstance(v,dict) and isinstance(r.get(k),dict) else v
 return r
def config(path:str)->Dict:
 c=json.loads(json.dumps(DEFAULT))
 if path and Path(path).exists():c=merge(c,json.loads(Path(path).read_text(encoding="utf-8")))
 return c
def refs(w:Path,base:str)->Tuple[str,str]:
 if base:return base,"HEAD"
 for e in ("GIT_PREVIOUS_SUCCESSFUL_COMMIT","GIT_PREVIOUS_COMMIT"):
  v=os.getenv(e)
  if v and cmd(["git","cat-file","-e",v+"^{commit}"],w)[0]==0:return v,"HEAD"
 if cmd(["git","rev-parse","--verify","HEAD~1"],w)[0]==0:return "HEAD~1","HEAD"
 return "HEAD","HEAD"
def allowed(path:str,c:Dict)->bool:
 p=path.replace("\\","/")
 if any(p==x.rstrip("/") or (x.endswith("/") and p.startswith(x)) for x in c["scan"]["exclude"]):return False
 return Path(p).name in c["scan"]["names"] or Path(p).suffix.lower() in c["scan"]["extensions"]
def files(w:Path,b:str,h:str,c:Dict)->List[Tuple[str,str]]:
 out=[]
 for line in git(w,"diff","--name-status","--find-renames",b,h).splitlines():
  p=line.split("\t"); status=p[0][0] if p else ""; name=p[-1] if len(p)>1 else ""
  if status!="D" and allowed(name,c) and (w/name).is_file():out.append((status,name))
 return out
def diff_rows(text:str)->Tuple[List[Row],Set[int],int,int]:
 rows=[]; added_lines=set(); old=new=None; plus=minus=0
 for raw in text.splitlines():
  m=re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@",raw)
  if m:old,new=int(m.group(1)),int(m.group(2));continue
  if old is None or raw.startswith(("diff ","index ","--- ","+++ ")):continue
  if raw.startswith("+"):rows.append(Row(None,new,"",raw[1:],"added"));added_lines.add(new);new+=1;plus+=1
  elif raw.startswith("-"):rows.append(Row(old,None,raw[1:],"","deleted"));old+=1;minus+=1
  elif raw.startswith(" "):rows.append(Row(old,new,raw[1:],raw[1:],"context"));old+=1;new+=1
 return rows,added_lines,plus,minus
def scan(path:str,lines:List[str],added:Set[int])->List[Finding]:
 out=[]
 for n in sorted(added):
  if not 1<=n<=len(lines):continue
  code=lines[n-1]
  for rid,sev,cat,pat,title,desc,rec in RULES:
   if pat.search(code):out.append(Finding(hashlib.sha1(f"{path}:{n}:{rid}".encode()).hexdigest()[:10],path,n,sev,cat,title,desc,rec,code))
 return out
def history(path:Path)->List[Dict[str,Any]]:
 try:return json.loads(path.read_text(encoding="utf-8"))
 except:return []
def esc(x:Any)->str:return html.escape(str(x),quote=True)

def css()->str:
 return """:root{--bg:#f6f8fb;--card:#fff;--ink:#172033;--muted:#667085;--line:#e6eaf0;--green:#138a59;--red:#c4322b;--amber:#c77800;--blue:#2563eb}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 Segoe UI,Arial,sans-serif}.mast{background:#172033;color:#fff;padding:24px}.wrap{max-width:1400px;margin:auto}.mast h1{margin:0;font-size:24px}.mast p{margin:5px 0 0;color:#cbd5e1}.content{padding:22px}.summary{display:grid;grid-template-columns:240px 1fr;gap:18px}.card,.file{background:#fff;border:1px solid var(--line);border-radius:12px;box-shadow:0 2px 8px #1118270a}.decision{padding:22px;text-align:center}.ring{width:92px;height:92px;margin:auto;border-radius:50%;display:grid;place-items:center;color:#fff;font-size:40px;font-weight:700}.ring.good{background:var(--green)}.ring.warning{background:var(--amber)}.ring.fail{background:var(--red)}.decision h2{margin:12px 0 2px}.score{font-size:28px;font-weight:750}.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.kpi{padding:16px}.kpi span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.kpi b{font-size:20px;display:block;margin-top:6px;overflow-wrap:anywhere}.charts{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0}.panel{padding:18px}.panel h2{font-size:16px;margin:0 0 14px}.bars{display:grid;gap:10px}.bar-row{display:grid;grid-template-columns:80px 1fr 30px;align-items:center;gap:10px}.bar{height:10px;background:#eef1f5;border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}.critical i{background:#a61b1b}.high i{background:#dc3b31}.medium i{background:#e58b13}.low i{background:#3b82f6}.trend{display:flex;align-items:end;gap:10px;height:120px;border-bottom:1px solid var(--line);padding:8px}.trend div{flex:1;background:#2563eb;border-radius:4px 4px 0 0;min-height:3px;position:relative}.trend small{position:absolute;bottom:-24px;width:100%;text-align:center;color:var(--muted)}.reasons{margin:18px 0}.file{margin:18px 0;overflow:hidden}.file-head{display:flex;justify-content:space-between;padding:16px 18px;border-bottom:1px solid var(--line)}.file-head h2{font-size:16px;margin:0}.delta{display:flex;gap:12px;color:var(--muted)}.plus{color:var(--green)}.minus{color:var(--red)}.diff-wrap{overflow:auto}.diff{width:100%;border-collapse:collapse;table-layout:fixed}.diff th{background:#f8fafc;text-align:left;color:var(--muted);font-size:11px;padding:9px}.diff td{padding:5px 8px;border-top:1px solid #f1f3f6;vertical-align:top}.ln{width:48px;text-align:right;color:#98a2b3}.mark{width:30px}.before,.after{width:calc(50% - 63px)}code{font:12px Consolas,monospace;white-space:pre-wrap;word-break:break-word}.added .after{background:#eaf8f0}.deleted .before{background:#fff0ef}.dot{font-size:17px}.dot.CRITICAL,.dot.HIGH{color:var(--red)}.dot.MEDIUM{color:var(--amber)}.dot.LOW{color:var(--blue)}.findings{padding:16px;background:#fafbfc}.finding{background:#fff;border:1px solid var(--line);border-left:4px solid #64748b;border-radius:8px;padding:13px;margin:10px 0}.finding.CRITICAL,.finding.HIGH{border-left-color:var(--red)}.finding.MEDIUM{border-left-color:var(--amber)}.finding.LOW{border-left-color:var(--blue)}.finding-top{display:flex;gap:9px;align-items:center}.finding-top em{margin-left:auto;color:var(--muted);font-style:normal}.badge{font-size:10px;font-weight:700;background:#eef1f5;padding:3px 7px;border-radius:10px}.snippet{background:#172033;color:#e5e7eb;padding:9px;border-radius:6px;overflow:auto}.clean{padding:14px;background:#eaf8f0;color:#0b6b43;border-radius:8px}.empty{text-align:center;padding:44px}.footer{text-align:center;color:var(--muted);font-size:12px;padding:22px}@media(max-width:850px){.summary,.charts{grid-template-columns:1fr}.kpis{grid-template-columns:1fr 1fr}}"""
def render(r:Dict[str,Any],out:Path):
 out.mkdir(parents=True,exist_ok=True);(out/"assets").mkdir(exist_ok=True);(out/"assets"/"reviewer.css").write_text(css(),encoding="utf-8")
 counts=r["counts"]; total=max(sum(counts.values()),1)
 bars="".join(f'<div class="bar-row {s.lower()}"><span>{s.title()}</span><div class="bar"><i style="width:{counts.get(s,0)/total*100:.1f}%"></i></div><b>{counts.get(s,0)}</b></div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW"])
 trend="".join(f'<div style="height:{max(3,int(x["score"]))}%"><small>{esc(x["build"])}</small></div>' for x in r["trend"])
 sections=[]
 for f in r["files"]:
  by={}
  for x in f["findings"]:by.setdefault(x["line"],[]).append(x)
  rows=[]
  for x in f["rows"]:
   marks="".join(f'<span class="dot {q["severity"]}" title="{esc(q["title"])}">●</span>' for q in by.get(x["new"] or -1,[]))
   rows.append(f'<tr class="{x["kind"]}"><td class="mark">{marks}</td><td class="ln">{x["old"] or ""}</td><td class="before"><code>{esc(x["before"])}</code></td><td class="ln">{x["new"] or ""}</td><td class="after"><code>{esc(x["after"])}</code></td></tr>')
  cards=[]
  for x in f["findings"]:cards.append(f'<article class="finding {x["severity"]}"><div class="finding-top"><span class="badge">{x["severity"]}</span><b>{esc(x["title"])}</b><em>Line {x["line"]}</em></div><pre class="snippet"><code>{esc(x["code"])}</code></pre><p>{esc(x["description"])}</p><p><strong>Recommended action:</strong> {esc(x["recommendation"])}</p></article>')
  sections.append(f'<section class="file"><div class="file-head"><h2>{esc(f["path"])}</h2><div class="delta"><span class="plus">+{f["added"]}</span><span class="minus">-{f["deleted"]}</span><span>{len(f["findings"])} finding(s)</span></div></div><div class="diff-wrap"><table class="diff"><thead><tr><th></th><th>#</th><th>Before</th><th>#</th><th>After</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div><div class="findings">{"".join(cards) if cards else "<div class=clean>No findings in added lines.</div>"}</div></section>')
 icon={"GOOD":"✓","WARNING":"!","FAIL":"×"}[r["status"]]
 doc=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Changed-Code Review</title><link rel="stylesheet" href="assets/reviewer.css"></head><body><header class="mast"><div class="wrap"><h1>Changed-Code Review</h1><p>Commit {esc(r["commit_short"])} · {esc(r["message"])}</p></div></header><main class="wrap content"><section class="summary"><div class="card decision"><div class="ring {r["status"].lower()}">{icon}</div><h2>{r["status"]}</h2><div class="score">{r["score"]}/100</div><p>Quality gate: <b>{r["gate"]}</b></p></div><div class="kpis"><div class="card kpi"><span>Changed files</span><b>{len(r["files"])}</b></div><div class="card kpi"><span>Findings</span><b>{r["total"]}</b></div><div class="card kpi"><span>Code delta</span><b><i class="plus">+{r["added"]}</i> <i class="minus">-{r["deleted"]}</i></b></div><div class="card kpi"><span>Author</span><b>{esc(r["author"])}</b></div><div class="card kpi"><span>Commit</span><b>{esc(r["commit_short"])}</b></div><div class="card kpi"><span>Build</span><b>{esc(r["build"])}</b></div><div class="card kpi"><span>Base</span><b>{esc(r["base"][:12])}</b></div><div class="card kpi"><span>Head</span><b>{esc(r["head"])}</b></div></div></section><section class="charts"><div class="card panel"><h2>Severity profile</h2><div class="bars">{bars}</div></div><div class="card panel"><h2>Quality trend</h2><div class="trend">{trend}</div></div></section><section class="card panel reasons"><h2>Review decision</h2><ul>{''.join(f'<li>{esc(x)}</li>' for x in r["reasons"])}</ul></section>{''.join(sections) if sections else '<section class="card empty"><h2>No reviewable source changes</h2><p>This commit did not add or modify a supported source file.</p></section>'}<div class="footer">Generated {esc(r["generated"])} · Read-only analysis of added lines only</div></main></body></html>'''
 (out/"index.html").write_text(doc,encoding="utf-8")

def main()->int:
 ap=argparse.ArgumentParser();ap.add_argument("--workspace",default=".");ap.add_argument("--config",default="");ap.add_argument("--base",default="");ap.add_argument("--output",default="review-output");ap.add_argument("--fail-build",default="false");a=ap.parse_args();w=Path(a.workspace).resolve();c=config(a.config);b,h=refs(w,a.base);review=[];allf=[];plus=minus=0
 for status,path in files(w,b,h,c):
  text=git(w,"diff","--unified=4","--no-color",b,h,"--",path);rows,added,p,m=diff_rows(text);lines=(w/path).read_text(encoding="utf-8",errors="replace").splitlines();f=scan(path,lines,added);review.append(FileReview(path,status,p,m,rows,f));allf+=f;plus+=p;minus+=m
 counts={s:sum(x.severity==s for x in allf) for s in WEIGHTS};score=max(0,100-sum(WEIGHTS[x.severity] for x in allf));status="GOOD" if score>=c["thresholds"]["good"] else "WARNING" if score>=c["thresholds"]["warning"] else "FAIL";gate="PASS" if counts["CRITICAL"]<=c["thresholds"]["max_critical"] and counts["HIGH"]<=c["thresholds"]["max_high"] and status!="FAIL" else "FAIL";reasons=[]
 if counts["CRITICAL"]:reasons.append(f'{counts["CRITICAL"]} critical finding(s) require attention.')
 if counts["HIGH"]>c["thresholds"]["max_high"]:reasons.append(f'{counts["HIGH"]} high findings exceed the configured maximum.')
 if not reasons:reasons.append("Changed code passed the configured checks.")
 hp=w/c["history"]["file"];hist=history(hp);commit=git(w,"rev-parse",h);entry={"build":os.getenv("BUILD_NUMBER",str(len(hist)+1)),"score":score,"commit":commit[:8]};hist.append(entry);hist=hist[-c["history"]["max"]:];hp.write_text(json.dumps(hist,indent=2),encoding="utf-8")
 r={"generated":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),"commit_short":commit[:8],"message":git(w,"log","-1","--pretty=%s"),"author":git(w,"log","-1","--pretty=%an"),"base":b,"head":h,"build":os.getenv("BUILD_NUMBER","local"),"files":[asdict(x) for x in review],"counts":counts,"total":len(allf),"added":plus,"deleted":minus,"score":score,"status":status,"gate":gate,"reasons":reasons,"trend":hist}
 out=w/a.output;out.mkdir(parents=True,exist_ok=True);(out/"review.json").write_text(json.dumps(r,indent=2),encoding="utf-8");render(r,out);print(f"Reviewer v{VERSION} | {status} | {score}/100 | files {len(review)} | findings {len(allf)}");return 2 if a.fail_build.lower()=="true" and gate=="FAIL" else 0
if __name__=="__main__":raise SystemExit(main())
