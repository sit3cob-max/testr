#!/usr/bin/env python3
import argparse, hashlib, json, os, re, subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional
RULES=[('CRITICAL','Security',re.compile(r'(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[\'\"][^\'\"]{6,}[\'\"]'),'Hardcoded credential','Store secrets in Jenkins Credentials or an approved secret store.'),('HIGH','Security',re.compile(r'\beval\s*\('),'Unsafe eval usage','Replace eval() with explicit parsing.'),('HIGH','Security',re.compile(r'shell\s*=\s*True'),'Shell injection exposure','Pass arguments as a list and keep shell=False.'),('MEDIUM','Reliability',re.compile(r'except\s*:\s*$'),'Bare exception handler','Catch specific exception types.'),('LOW','Maintainability',re.compile(r'(?i)\b(todo|fixme)\b'),'Unfinished work marker','Complete it or link it to a tracked work item.'),('LOW','Maintainability',re.compile(r'\bprint\s*\(|console\.log\s*\('),'Debug output','Use structured logging.')]
EXT={'.py','.java','.js','.ts','.tsx','.jsx','.c','.cpp','.h','.hpp','.cs','.go','.rs','.sh','.ps1','.yaml','.yml','.gradle','.groovy'}
EXCLUDE=('jenkins/','review-ui/','review-output/','.git/','node_modules/','build/','target/','venv/','.venv/')
@dataclass
class Row: old:Optional[int]; new:Optional[int]; before:str; after:str; kind:str

def run(a,cwd):return subprocess.run(a,cwd=str(cwd),text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout.strip()
def parse_diff(text):
 rows=[]; added=set(); old=new=None; plus=minus=0
 for line in text.splitlines():
  m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@',line)
  if m:old,new=map(int,m.groups());continue
  if old is None or line.startswith(('diff ','index ','--- ','+++ ')):continue
  if line.startswith('+'):rows.append(Row(None,new,'',line[1:],'added'));added.add(new);new+=1;plus+=1
  elif line.startswith('-'):rows.append(Row(old,None,line[1:],'','deleted'));old+=1;minus+=1
  elif line.startswith(' '):rows.append(Row(old,new,line[1:],line[1:],'context'));old+=1;new+=1
 return rows,added,plus,minus
def main():
 p=argparse.ArgumentParser();p.add_argument('--workspace',default='.');p.add_argument('--output',default='review-output/review.json');a=p.parse_args();w=Path(a.workspace).resolve()
 prev=os.getenv('GIT_PREVIOUS_SUCCESSFUL_COMMIT') or os.getenv('GIT_PREVIOUS_COMMIT') or 'HEAD~1'; head='HEAD'
 names=run(['git','diff','--name-status',prev,head],w).splitlines(); files=[]; allfind=[]; add=delete=0
 for item in names:
  bits=item.split('\t'); status=bits[0][:1]; name=bits[-1].replace('\\','/')
  if status=='D' or name.startswith(EXCLUDE) or (Path(name).suffix.lower() not in EXT and Path(name).name not in {'Dockerfile','Jenkinsfile'}):continue
  path=w/name
  if not path.exists():continue
  diff=run(['git','diff','--unified=4','--no-color',prev,head,'--',name],w); rows,added,pn,mn=parse_diff(diff); lines=path.read_text(encoding='utf-8',errors='replace').splitlines(); findings=[]
  for n in sorted(added):
   if 1<=n<=len(lines):
    code=lines[n-1]
    for sev,cat,pat,title,rec in RULES:
     if pat.search(code):
      q={'id':hashlib.sha1(f'{name}:{n}:{title}'.encode()).hexdigest()[:10],'line':n,'severity':sev,'category':cat,'title':title,'code':code,'description':title+' detected in changed code.','recommendation':rec};findings.append(q);allfind.append(q)
  files.append({'path':name,'status':status,'added':pn,'deleted':mn,'rows':[asdict(x) for x in rows],'findings':findings});add+=pn;delete+=mn
 counts={s:sum(x['severity']==s for x in allfind) for s in ['CRITICAL','HIGH','MEDIUM','LOW']};score=max(0,100-counts['CRITICAL']*30-counts['HIGH']*12-counts['MEDIUM']*5-counts['LOW']);status='GOOD' if score>=85 else 'WARNING' if score>=60 else 'FAIL';gate='FAIL' if counts['CRITICAL'] or status=='FAIL' else 'PASS';commit=run(['git','rev-parse','HEAD'],w)
 data={'score':score,'status':status,'gate':gate,'commit_short':commit[:8],'message':run(['git','log','-1','--pretty=%s'],w),'author':run(['git','log','-1','--pretty=%an'],w),'build':os.getenv('BUILD_NUMBER','local'),'base':prev,'head':head,'counts':counts,'total':len(allfind),'added':add,'deleted':delete,'reasons':['Changed code passed configured checks.'] if not allfind else [f'{len(allfind)} finding(s) detected in added lines.'],'files':files}
 out=w/a.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(data,indent=2),encoding='utf-8');print(f"{status} {score}/100 | changed files {len(files)} | findings {len(allfind)}")
if __name__=='__main__':main()
