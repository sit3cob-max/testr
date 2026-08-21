#!/usr/bin/env python3
"""Changed-code MISRA/AUTOSAR heuristic pre-check for Jenkins.

It intentionally does not claim formal compliance. It detects a practical,
documented subset of source patterns and emits machine-readable evidence.
"""
import argparse, hashlib, json, os, re, subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

SEV_WEIGHT={"CRITICAL":30,"HIGH":12,"MEDIUM":5,"LOW":1}
SOURCE_EXT={'.c','.h','.cpp','.cc','.cxx','.hpp','.hh','.hxx'}
EXCLUDE=('dashboard/','review-output/','.git/','node_modules/','build/','target/','venv/','.venv/','__pycache__/')
C_KEYWORDS={'auto','break','case','char','const','continue','default','do','double','else','enum','extern','float','for','goto','if','inline','int','long','register','restrict','return','short','signed','sizeof','static','struct','switch','typedef','union','unsigned','void','volatile','while','alignas','alignof','and','and_eq','asm','bitand','bitor','bool','catch','class','compl','constexpr','const_cast','delete','dynamic_cast','explicit','export','false','friend','mutable','namespace','new','noexcept','not','not_eq','nullptr','operator','or','or_eq','private','protected','public','reinterpret_cast','static_assert','static_cast','template','this','thread_local','throw','true','try','typeid','typename','using','virtual','wchar_t','xor','xor_eq'}

RULES=[
 ("MISRA-D4.12","MISRA C:2012","Required","CRITICAL","Memory",re.compile(r'\b(malloc|calloc|realloc|free)\s*\('),"Dynamic memory allocation","Heap allocation/deallocation is used in changed code.","Fragmentation, allocation failure, leaks, and non-deterministic execution may affect safety.","Use fixed-size storage, stack/static allocation, or a project-approved deterministic pool."),
 ("MISRA-21.3","MISRA C:2012","Required","CRITICAL","Memory",re.compile(r'\b(malloc|calloc|realloc|free)\s*\('),"stdlib memory function","A prohibited allocation/deallocation function is used.","The memory behavior is difficult to bound and verify.","Remove the function and use approved deterministic storage."),
 ("MISRA-21.6","MISRA C:2012","Required","HIGH","Library",re.compile(r'\b(printf|scanf|fprintf|sprintf|snprintf|fopen|fclose|gets|puts)\s*\('),"Standard I/O usage","A standard I/O function is used directly.","Implementation-defined behavior, blocking, and unbounded formatting may affect determinism.","Use the project-approved logging, diagnostics, or I/O abstraction."),
 ("MISRA-20.4","MISRA C:2012","Required","HIGH","Preprocessor",re.compile(r'^\s*#\s*define\s+([A-Za-z_]\w*)'),"Macro name requires keyword check","A macro definition was introduced.","Redefining a keyword or reserved identifier can change language semantics.","Use a project-unique macro name that is not a C/C++ keyword."),
 ("MISRA-11.3","MISRA C:2012","Required","HIGH","Type Safety",re.compile(r'\([^\n)]*\*\s*\)\s*[A-Za-z_(]'),"C-style pointer cast","A cast to a pointer type is present.","Alignment, aliasing, and object representation assumptions may be invalid.","Use a type-safe design, memcpy for byte representation, or an approved documented deviation."),
 ("MISRA-12.2","MISRA C:2012","Required","HIGH","Arithmetic",re.compile(r'(<<|>>)\s*(\d+)\b'),"Shift range requires validation","A constant shift operation is present.","A shift count outside the left operand width can be undefined.","Use a fixed-width unsigned operand and prove the shift count is lower than its bit width."),
 ("MISRA-14.4","MISRA C:2012","Required","MEDIUM","Control Flow",re.compile(r'\b(if|while)\s*\(\s*([A-Za-z_]\w*)\s*\)'),"Non-explicit Boolean condition","A single identifier controls a branch/loop without an explicit comparison.","Integer or pointer truthiness can obscure intent and essential type behavior.","Compare explicitly against zero, NULL/nullptr, or a boolean value."),
 ("AUTOSAR-A0-4-2","AUTOSAR C++14","Required","HIGH","Types",re.compile(r'\blong\s+double\b'),"long double is prohibited","The implementation-dependent long double type is used.","Its representation and precision can differ by toolchain.","Use an approved fixed floating-point type and document numerical requirements."),
 ("AUTOSAR-A2-14-3","AUTOSAR C++14","Required","HIGH","Types",re.compile(r'\bwchar_t\b'),"wchar_t is prohibited","wchar_t has implementation-defined width.","Text width and representation can vary across platforms.","Use char16_t or char32_t where appropriate."),
 ("AUTOSAR-A3-1-3","AUTOSAR C++14","Advisory","LOW","Files",re.compile(r'.'),"Implementation file extension","A changed implementation file does not use .cpp.","Inconsistent extensions reduce build and tooling consistency.","Rename project-local C++ implementation files to .cpp."),
 ("AUTOSAR-A5-1-2","AUTOSAR C++14","Required","HIGH","Lambda",re.compile(r'\[\s*[=&]\s*\]\s*\('),"Implicit lambda capture","The lambda captures variables implicitly.","Implicit capture hides dependencies and can extend object lifetimes unexpectedly.","List every captured variable explicitly."),
 ("AUTOSAR-A5-1-3","AUTOSAR C++14","Required","MEDIUM","Lambda",re.compile(r'\[[^\]]*\]\s*\{'),"Lambda parameter list omitted","The lambda omits an explicit parameter list.","Uniform syntax and analyzability are reduced.","Write an explicit empty parameter list: []()."),
 ("AUTOSAR-A5-2-1","AUTOSAR C++14","Advisory","MEDIUM","Casts",re.compile(r'\bdynamic_cast\s*<'),"dynamic_cast usage","A run-time type checked cast is used.","Run-time type information and dynamic checks can affect predictability.","Prefer a design that does not require downcasting."),
 ("AUTOSAR-M5-0-14","AUTOSAR C++14","Required","MEDIUM","Expressions",re.compile(r'\?\s*[^:]+\s*:'),"Conditional operator requires Boolean condition","A conditional operator is present.","The first operand may not have bool type or may hide complex behavior.","Ensure the condition is bool and keep the expression simple."),
 ("AUTOSAR-M5-0-15","AUTOSAR C++14","Required","HIGH","Pointers",re.compile(r'\b[A-Za-z_]\w*\s*[+\-]=?\s*\d+\b'),"Possible pointer arithmetic","Arithmetic on an identifier was introduced.","If the operand is a pointer, arithmetic can escape array bounds.","Use array indexing or an approved bounds-aware abstraction."),
 ("AUTOSAR-M5-0-21","AUTOSAR C++14","Required","HIGH","Bitwise",re.compile(r'(?<![&|])\b[A-Za-z_]\w*\s*([&|^])\s*[A-Za-z_0-9]'),"Bitwise operand type requires validation","A bitwise operation is present.","Signed operands may produce implementation-dependent or surprising values.","Use unsigned underlying types and make widths explicit."),
 ("AUTOSAR-A5-5-1","AUTOSAR C++14","Required","HIGH","Arithmetic",re.compile(r'[/%%]\s*([A-Za-z_]\w*|0)\b'),"Division/remainder denominator requires validation","A division or remainder operation is present.","A zero denominator causes a run-time failure or undefined behavior.","Prove or check that the right operand is not zero before evaluation."),
 ("AUTOSAR-A5-16-1","AUTOSAR C++14","Required","MEDIUM","Expressions",re.compile(r'\([^;]*\?[^:]+:[^)]*\)\s*[+\-*/]'),"Ternary used as sub-expression","A conditional expression appears inside a larger arithmetic expression.","Complex evaluation reduces readability and reviewability.","Assign the ternary result to a named variable before further use."),
 ("AUTOSAR-A6-5-3","AUTOSAR C++14","Advisory","LOW","Control Flow",re.compile(r'\bdo\s*\{?'),"do statement","A do loop executes once before checking its condition.","The exit condition can be overlooked during review.","Prefer while or for when behavior can be expressed clearly."),
 ("AUTOSAR-A7-1-4","AUTOSAR C++14","Required","HIGH","Declarations",re.compile(r'\bregister\b'),"register keyword","The deprecated register keyword is used.","The keyword is obsolete and ignored by modern compilers.","Remove register and allow the compiler to optimize."),
 ("AUTOSAR-M7-3-4","AUTOSAR C++14","Required","HIGH","Namespaces",re.compile(r'^\s*using\s+namespace\s+'),"using-directive","A using namespace directive is present.","It pollutes lookup scope and can create ambiguous bindings.","Use qualified names or narrow using-declarations."),
 ("AUTOSAR-A15-1-2","AUTOSAR C++14","Required","HIGH","Exceptions",re.compile(r'\bthrow\s+[^;]*\*'),"Pointer exception","A pointer may be thrown as an exception object.","Ownership and lifetime of the exception object are unclear.","Throw a value type derived from std::exception where applicable."),
 ("AUTOSAR-A15-5-2","AUTOSAR C++14","Required","CRITICAL","Termination",re.compile(r'\b(std::)?(abort|exit|quick_exit|_Exit)\s*\('),"Abrupt termination","A termination function is called.","The program may stop without controlled cleanup or safe-state transition.","Return an error through the approved safety mechanism."),
 ("AUTOSAR-A16-6-1","AUTOSAR C++14","Required","HIGH","Preprocessor",re.compile(r'^\s*#\s*error\b'),"#error directive","The source contains a preprocessing hard failure.","Build behavior can depend on configuration paths not modeled in runtime analysis.","Use project-approved configuration validation."),
 ("AUTOSAR-A16-7-1","AUTOSAR C++14","Required","HIGH","Preprocessor",re.compile(r'^\s*#\s*pragma\b'),"#pragma directive","A compiler-specific pragma is used.","Portability and toolchain consistency may be reduced.","Use standard C++14 constructs or an approved isolated wrapper/deviation."),
 ("AUTOSAR-A18-0-3","AUTOSAR C++14","Required","HIGH","Library",re.compile(r'#\s*include\s*[<\"](clocale|locale\.h)[>\"]'),"Locale library usage","Locale facilities are included.","Locale-dependent behavior can change parsing and formatting.","Use locale-independent project utilities."),
 ("AUTOSAR-A18-1-2","AUTOSAR C++14","Required","HIGH","Containers",re.compile(r'\bstd::vector\s*<\s*bool\s*>'),"std::vector<bool>","The specialized bit container is used.","Proxy references and packed representation differ from normal vector semantics.","Use std::vector<uint8_t>, std::array, or a dedicated bitset abstraction."),
 ("AUTOSAR-A18-1-3","AUTOSAR C++14","Required","CRITICAL","Memory",re.compile(r'\bstd::auto_ptr\s*<'),"std::auto_ptr","The removed ownership type is used.","Copying transfers ownership implicitly and can cause unexpected null pointers.","Use std::unique_ptr with explicit move semantics."),
]

@dataclass
class DiffRow:
    old: Optional[int]
    new: Optional[int]
    before: str
    after: str
    kind: str

def run(args,cwd):
    p=subprocess.run(args,cwd=str(cwd),text=True,errors='replace',stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    return p.returncode,p.stdout.strip(),p.stderr.strip()
def git(w,*args): return run(['git',*args],w)[1]
def parse_diff(text):
    rows=[]; added=set(); old=new=None; plus=minus=0
    for line in text.splitlines():
        m=re.match(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@',line)
        if m: old,new=map(int,m.groups()); continue
        if old is None or line.startswith(('diff ','index ','--- ','+++ ')): continue
        if line.startswith('+'): rows.append(DiffRow(None,new,'',line[1:],'added')); added.add(new); new+=1; plus+=1
        elif line.startswith('-'): rows.append(DiffRow(old,None,line[1:],'','deleted')); old+=1; minus+=1
        elif line.startswith(' '): rows.append(DiffRow(old,new,line[1:],line[1:],'context')); old+=1; new+=1
    return rows,added,plus,minus
def finding(rule,file,line,code,confidence='heuristic'):
    rid,std,obl,sev,cat,pat,title,root,risk,fix=rule
    return dict(id=hashlib.sha1(f'{file}:{line}:{rid}'.encode()).hexdigest()[:12],rule_id=rid,standard=std,obligation=obl,severity=sev,category=cat,title=title,file=file,line=line,code=code,root_cause=root,risk_explanation=risk,fix_recommendation=fix,confidence=confidence,source='changed-code heuristic')
def special_findings(name,path,source,added,enabled):
    out=[]
    suffix=path.suffix.lower()
    if 'AUTOSAR-A3-1-3' in enabled and suffix in {'.cc','.cxx'}:
        out.append(dict(id='fileext-'+hashlib.sha1(name.encode()).hexdigest()[:8],rule_id='AUTOSAR-A3-1-3',standard='AUTOSAR C++14',obligation='Advisory',severity='LOW',category='Files',title='Non-standard implementation extension',file=name,line=1,code=name,root_cause='A project-local C++ implementation file does not use the .cpp extension.',risk_explanation='Inconsistent extensions can reduce tooling and build consistency.',fix_recommendation='Rename the file to use .cpp if allowed by project policy.',confidence='high',source='file metadata'))
    if 'AUTOSAR-M7-3-3' in enabled and suffix in {'.h','.hpp','.hh','.hxx'}:
        for i,line in enumerate(source,1):
            if i in added and re.search(r'\bnamespace\s*\{',line):
                out.append(dict(id=hashlib.sha1(f'{name}:{i}:M7-3-3'.encode()).hexdigest()[:12],rule_id='AUTOSAR-M7-3-3',standard='AUTOSAR C++14',obligation='Required',severity='HIGH',category='Namespaces',title='Unnamed namespace in header',file=name,line=i,code=line,root_cause='An unnamed namespace is declared in a header.',risk_explanation='Each translation unit receives distinct internal-linkage entities.',fix_recommendation='Move implementation details to a source file or use an explicit namespace.',confidence='high',source='changed-code heuristic'))
    return out
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--workspace',default='.');ap.add_argument('--config',default='dashboard/config/rules.json');ap.add_argument('--output',default='review-output/review.json');ap.add_argument('--base',default='');args=ap.parse_args();w=Path(args.workspace).resolve();cfg=json.loads((w/args.config).read_text(encoding='utf-8'));enabled=set(cfg['enabled_rules'])
    base=args.base or os.getenv('GIT_PREVIOUS_SUCCESSFUL_COMMIT') or os.getenv('GIT_PREVIOUS_COMMIT') or 'HEAD~1'
    if run(['git','rev-parse','--verify',base],w)[0]!=0: base='HEAD~1'
    files=[];all_findings=[];total_add=total_del=0
    for rec in git(w,'diff','--name-status',base,'HEAD').splitlines():
        parts=rec.split('\t'); status=parts[0][:1]; name=parts[-1].replace('\\','/')
        if status=='D' or name.startswith(EXCLUDE) or Path(name).suffix.lower() not in SOURCE_EXT: continue
        path=w/name
        if not path.exists(): continue
        rows,added,pn,mn=parse_diff(git(w,'diff','--unified=4','--no-color',base,'HEAD','--',name)); source=path.read_text(encoding='utf-8',errors='replace').splitlines(); ff=[]
        for num in sorted(added):
            if not 1<=num<=len(source): continue
            code=source[num-1]
            for rule in RULES:
                if rule[0] not in enabled: continue
                match=rule[5].search(code)
                if not match: continue
                if rule[0]=='MISRA-20.4' and match.group(1) not in C_KEYWORDS: continue
                if rule[0]=='AUTOSAR-M5-0-15' and not any(t in code for t in ('*','ptr','Ptr','pointer')): continue
                if rule[0]=='AUTOSAR-A5-5-1' and re.search(r'[/%%]\s*[1-9]\d*[UuLl]*\b',code): continue
                ff.append(finding(rule,name,num,code))
        ff.extend(special_findings(name,path,source,added,enabled))
        dedup={(x['rule_id'],x['line'],x['code']):x for x in ff};ff=list(dedup.values());all_findings.extend(ff);files.append(dict(path=name,status=status,added=pn,deleted=mn,rows=[asdict(x) for x in rows],findings=ff));total_add+=pn;total_del+=mn
    counts={s:sum(x['severity']==s for x in all_findings) for s in SEV_WEIGHT};score=max(0,100-sum(SEV_WEIGHT[x['severity']] for x in all_findings));th=cfg['thresholds'];status='GOOD' if score>=th['good'] else 'WARNING' if score>=th['warning'] else 'FAIL';gate='FAIL' if counts['CRITICAL']>th['max_critical'] or counts['HIGH']>th['max_high'] or status=='FAIL' else 'PASS';commit=git(w,'rev-parse','HEAD')
    data=dict(version='5.0.0',profile=cfg['profile'],disclaimer=cfg['disclaimer'],score=score,status=status,gate=gate,commit_short=commit[:8],message=git(w,'log','-1','--pretty=%s'),author=git(w,'log','-1','--pretty=%an'),build=os.getenv('BUILD_NUMBER','local'),base=base,head='HEAD',counts=counts,total=len(all_findings),added=total_add,deleted=total_del,rules_enabled=len(enabled),files=files,reasons=['No configured heuristic violations in added lines.'] if not all_findings else [f'{len(all_findings)} configured heuristic finding(s) detected.'])
    out=w/args.output;out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(data,indent=2),encoding='utf-8');print(f"Compliance pre-check v5 | {status} | {score}/100 | files {len(files)} | findings {len(all_findings)} | rules {len(enabled)}")
if __name__=='__main__': main()
