#!/usr/bin/env python3
import argparse,hashlib,json,os,re,subprocess
from dataclasses import dataclass,asdict
from pathlib import Path
from typing import Optional
EXT={'.c','.h','.cpp','.cc','.cxx','.hpp','.hh','.hxx'}
EXCLUDE=('dashboard/','review-output/','.git/','build/','target/','node_modules/')
W={'CRITICAL':30,'HIGH':12,'MEDIUM':5,'LOW':1}
RULES=[
('MISRA-D4.12','CRITICAL','Memory','Dynamic memory used','Dynamic memory can fail.','Use static memory.',re.compile(r'\b(malloc|calloc|realloc|free)\s*\(')),
('MISRA-21.6','HIGH','Library','Standard I/O used','Standard I/O may not be predictable.','Use project logging.',re.compile(r'\b(printf|scanf|fprintf|sprintf|fopen|fclose)\s*\(')),
('MISRA-14.4','MEDIUM','Control flow','Condition is not explicit','The condition is hard to read.','Compare with 0, NULL, or true.',re.compile(r'\b(if|while)\s*\(\s*[A-Za-z_]\w*\s*\)')),
('AUTOSAR-A0-4-2','HIGH','Types','long double used','Its size can change by compiler.','Use an approved type.',re.compile(r'\blong\s+double\b')),
('AUTOSAR-A2-14-3','HIGH','Types','wchar_t used','Its width can change by compiler.','Use char16_t or char32_t.',re.compile(r'\bwchar_t\b')),
('AUTOSAR-M7-3-4','HIGH','Namespace','using namespace used','It can create name conflicts.','Use full names.',re.compile(r'^\s*using\s+namespace\s+')),
('AUTOSAR-A7-1-4','HIGH','Declaration','register used','The keyword is old and ignored.','Remove register.',re.compile(r'\bregister\b')),
('AUTOSAR-A15-5-2','CRITICAL','Termination','Program stops suddenly','Cleanup and safe shutdown may not run.','Return an error safely.',re.compile(r'\b(std::)?(abort|exit|quick_exit)\s*\(')),
('AUTOSAR-A16-7-1','HIGH','Portability','#pragma used','It may work only with one compiler.','Use standard code or an approved wrapper.',re.compile(r'^\s*#\s*pragma\b')),
('AUTOSAR-A18-1-2','HIGH','Container','vector<bool> used','It behaves differently from a normal vector.','Use vector<uint8_t> or bitset.',re.compile(r'\bstd::vector\s*<\s*bool\s*>')),
('AUTOSAR-A18-1-3','CRITICAL','Memory','auto_ptr used','Ownership can move unexpectedly.','Use unique_ptr.',re.compile(r'\bstd::auto_ptr\s*<'))]
@dataclass
class Row: old:Optional[int];new:Optional[int];before:str;after:str;kind:str
def run(a,c):
 p=subprocess.run(a,cwd=str(c),text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.PIPE);return p.returncode,p.stdout.strip()
def git(w,*a):return run(['git',*a],w)[1]
def parse(text):
 rows=[];added=set();old=new=None
 for s in text.splitlines():
  m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@',s)
  if m:old,new=map(int,m.groups());continue
  if old is None or s.startswith(('diff ','index ','--- ','+++ ')):continue
  if s.startswith('+'):rows.append(Row(None,new,'',s[1:],'added'));added.add(new);new+=1
  elif s.startswith('-'):rows.append(Row(old,None,s[1:],'','deleted'));old+=1
  elif s.startswith(' '):rows.append(Row(old,new,s[1:],s[1:],'context'));old+=1;new+=1
 return rows,added
def context(rows,line,radius):
 idx=next((i for i,r in enumerate(rows) if r.new==line),0);return [asdict(x) for x in rows[max(0,idx-radius):min(len(rows),idx+radius+1)]]
def main():
 p=argparse.ArgumentParser();p.add_argument('--workspace',default='.');p.add_argument('--output',default='review-output/review.json');p.add_argument('--context',type=int,default=3);a=p.parse_args();w=Path(a.workspace).resolve();base=os.getenv('GIT_PREVIOUS_SUCCESSFUL_COMMIT') or os.getenv('GIT_PREVIOUS_COMMIT') or 'HEAD~1'
 if run(['git','rev-parse','--verify',base],w)[0]!=0:base='HEAD~1'
 files=[];allq=[]
 for rec in git(w,'diff','--name-status',base,'HEAD').splitlines():
  x=rec.split('\t');name=x[-1].replace('\\','/');status=x[0][:1]
  if status=='D' or name.startswith(EXCLUDE) or Path(name).suffix.lower() not in EXT:continue
  path=w/name
  if not path.exists():continue
  rows,added=parse(git(w,'diff',f'--unified={a.context}','--no-color',base,'HEAD','--',name));lines=path.read_text(encoding='utf-8',errors='replace').splitlines();qs=[]
  for n in sorted(added):
   if not 1<=n<=len(lines):continue
   code=lines[n-1]
   for rid,sev,cat,issue,why,fix,pat in RULES:
    if pat.search(code):
     q={'id':hashlib.sha1(f'{name}:{n}:{rid}'.encode()).hexdigest()[:10],'rule':rid,'severity':sev,'category':cat,'issue':issue,'why':why,'fix':fix,'line':n,'code':code,'block':context(rows,n,a.context)};qs.append(q);allq.append(q)
  if qs:files.append({'path':name,'status':status,'findings':qs})
 counts={s:sum(q['severity']==s for q in allq) for s in W};score=max(0,100-sum(W[q['severity']] for q in allq));status='GOOD' if score>=85 else 'WARNING' if score>=60 else 'FAIL';commit=git(w,'rev-parse','HEAD');data={'score':score,'status':status,'gate':'FAIL' if counts['CRITICAL'] or status=='FAIL' else 'PASS','commit':commit[:8],'build':os.getenv('BUILD_NUMBER','local'),'counts':counts,'total':len(allq),'files':files}
 out=w/a.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(data,indent=2),encoding='utf-8');print(f'{status} {score}/100 | issue files {len(files)} | findings {len(allq)}')
if __name__=='__main__':main()
