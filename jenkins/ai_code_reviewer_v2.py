#!/usr/bin/env python3
"""AI Code Reviewer for Jenkins v2.0

Features:
- Reviews only files changed in the current Git commit/range
- Shows added and removed code in a side-by-side diff
- Reviews added lines only, avoiding historical/generated-file noise
- Excludes the reviewer, reports, build output, dependencies, and configurable paths
- Produces a self-contained visual HTML dashboard and JSON report
- Includes severity chart, score gauge, changed-file summary, and build trend
- Optional MCP review hook
- Read-only: never changes project source files

Python 3.8+, standard library only.
"""

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

PRODUCT = "AI Code Reviewer for Jenkins"
VERSION = "2.0.0"

DEFAULT_CONFIG: Dict[str, Any] = {
    "thresholds": {
        "good_score": 85,
        "warning_score": 60,
        "max_critical": 0,
        "max_high": 5
    },
    "scan": {
        "include_extensions": [
            ".py", ".java", ".js", ".ts", ".tsx", ".jsx", ".c", ".cpp",
            ".h", ".hpp", ".cs", ".go", ".rs", ".sh", ".bat", ".ps1",
            ".yaml", ".yml", ".gradle", ".groovy"
        ],
        "include_names": ["Dockerfile", "Jenkinsfile"],
        "exclude_paths": [
            ".git/", ".jenkins/", "node_modules/", "dist/", "build/", "target/",
            "venv/", ".venv/", "__pycache__/", ".pytest_cache/", ".idea/",
            ".vscode/", "jenkins/ai_code_reviewer_v1.py",
            "jenkins/ai_code_reviewer_v2.py", "ai_code_reviewer_v1.py",
            "ai_code_reviewer_v2.py", "ai_code_review_report.html",
            "ai_code_review_report.json", "ai_code_review_history.json"
        ],
        "max_file_size_kb": 768,
        "context_lines": 3
    },
    "mcp": {
        "enabled": False,
        "server_url": "",
        "token": "",
        "tool_name": "review_code_diff"
    },
    "history": {
        "file": "ai_code_review_history.json",
        "max_entries": 30
    }
}

RULES = [
    ("SECRET001", "CRITICAL", "Security", re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
     "Possible hardcoded secret", "A credential-like value appears to be hardcoded.",
     "Move the value to Jenkins Credentials, environment variables, or an approved secret store.",
     "Add a CI test that rejects committed credentials."),
    ("SEC101", "HIGH", "Security", re.compile(r"\beval\s*\("),
     "Unsafe eval usage", "eval() may execute untrusted code.",
     "Replace eval() with explicit parsing or a controlled mapping.",
     "Test malicious and malformed input and verify that execution is rejected."),
    ("SEC102", "HIGH", "Security", re.compile(r"\bexec\s*\("),
     "Unsafe exec usage", "exec() dynamically executes code.",
     "Replace exec() with explicit function dispatch.",
     "Test that unexpected input cannot trigger code execution."),
    ("SEC103", "HIGH", "Security", re.compile(r"shell\s*=\s*True"),
     "shell=True detected", "A shell command may become vulnerable to command injection.",
     "Pass arguments as a list and keep shell=False.",
     "Test input containing shell metacharacters."),
    ("ERR101", "MEDIUM", "Reliability", re.compile(r"except\s*:\s*$"),
     "Bare except detected", "A bare except may hide unexpected failures.",
     "Catch specific exception types and log useful context.",
     "Trigger the expected exception and verify the handling path."),
    ("TODO101", "LOW", "Maintainability", re.compile(r"(?i)\b(todo|fixme|hack|temporary workaround)\b"),
     "TODO or FIXME found", "The changed code contains unfinished or temporary work.",
     "Complete the work or link the comment to a tracked work item.",
     "Add coverage for the incomplete behavior before closing the task."),
    ("DBG101", "LOW", "Maintainability", re.compile(r"\bprint\s*\(|console\.log\s*\("),
     "Debug output found", "Debug output may add noise to production logs.",
     "Use structured logging at an appropriate level.",
     "Verify expected log events using a logger test fixture."),
]

SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 12, "MEDIUM": 5, "LOW": 1, "INFO": 0}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    id: str
    file: str
    line: int
    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    suggested_test: str
    code: str
    source: str = "local-rule"


@dataclass
class DiffRow:
    old_line: Optional[int]
    new_line: Optional[int]
    old_text: str
    new_text: str
    kind: str


@dataclass
class ChangedFile:
    path: str
    status: str
    added: int
    deleted: int
    rows: List[DiffRow] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ReviewReport:
    product: str
    version: str
    generated_at: str
    commit: str
    commit_short: str
    commit_message: str
    author: str
    base_ref: str
    head_ref: str
    build_number: str
    job_name: str
    changed_files: List[ChangedFile]
    counts: Dict[str, int]
    total_findings: int
    total_added: int
    total_deleted: int
    score: int
    status: str
    gate: str
    reasons: List[str]
    trend: List[Dict[str, Any]]


def run(command: Sequence[str], cwd: Path, check: bool = False) -> Tuple[int, str, str]:
    completed = subprocess.run(command, cwd=str(cwd), text=True, errors="replace",
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Command failed")
    return completed.returncode, completed.stdout, completed.stderr


def git(workspace: Path, *args: str, check: bool = False) -> str:
    return run(["git", *args], workspace, check=check)[1].strip()


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: Optional[str]) -> Dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        config_path = Path(path)
        if config_path.exists():
            config = deep_merge(config, json.loads(config_path.read_text(encoding="utf-8")))
    if os.getenv("MCP_SERVER_URL"):
        config["mcp"]["enabled"] = True
        config["mcp"]["server_url"] = os.environ["MCP_SERVER_URL"]
    if os.getenv("MCP_TOKEN"):
        config["mcp"]["token"] = os.environ["MCP_TOKEN"]
    return config


def determine_refs(workspace: Path, base_arg: Optional[str], head_arg: str) -> Tuple[str, str]:
    head = head_arg or "HEAD"
    if base_arg:
        return base_arg, head
    previous = os.getenv("GIT_PREVIOUS_SUCCESSFUL_COMMIT") or os.getenv("GIT_PREVIOUS_COMMIT")
    if previous and run(["git", "cat-file", "-e", f"{previous}^{{commit}}"], workspace)[0] == 0:
        return previous, head
    change_target = os.getenv("CHANGE_TARGET")
    if change_target:
        remote = f"origin/{change_target}"
        if run(["git", "rev-parse", "--verify", remote], workspace)[0] == 0:
            merge_base = git(workspace, "merge-base", remote, head)
            if merge_base:
                return merge_base, head
    if run(["git", "rev-parse", "--verify", "HEAD~1"], workspace)[0] == 0:
        return "HEAD~1", head
    empty_tree = git(workspace, "hash-object", "-t", "tree", "/dev/null") if os.name != "nt" else ""
    return (empty_tree or head), head


def is_excluded(path: str, config: Dict[str, Any]) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    for excluded in config["scan"]["exclude_paths"]:
        excluded_norm = excluded.replace("\\", "/").lstrip("./")
        if excluded_norm.endswith("/") and normalized.startswith(excluded_norm):
            return True
        if normalized == excluded_norm:
            return True
    name = Path(normalized).name
    suffix = Path(normalized).suffix.lower()
    return not (name in set(config["scan"]["include_names"]) or suffix in set(config["scan"]["include_extensions"]))


def changed_file_list(workspace: Path, base: str, head: str, config: Dict[str, Any]) -> List[Tuple[str, str]]:
    output = git(workspace, "diff", "--name-status", "--find-renames", base, head)
    result: List[Tuple[str, str]] = []
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0][0]
        path = parts[-1]
        if status == "D" or is_excluded(path, config):
            continue
        full = workspace / path
        if not full.exists() or full.stat().st_size > int(config["scan"]["max_file_size_kb"]) * 1024:
            continue
        result.append((status, path))
    return result


def parse_unified_diff(text: str) -> Tuple[List[DiffRow], Set[int], int, int]:
    rows: List[DiffRow] = []
    added_lines: Set[int] = set()
    old_line = new_line = None
    added = deleted = 0
    for raw in text.splitlines():
        if raw.startswith("@@"):
            match = re.search(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
            if match:
                old_line, new_line = int(match.group(1)), int(match.group(2))
            continue
        if raw.startswith(("diff --git", "index ", "--- ", "+++ ")) or old_line is None or new_line is None:
            continue
        if raw.startswith("+"):
            rows.append(DiffRow(None, new_line, "", raw[1:], "added"))
            added_lines.add(new_line)
            new_line += 1
            added += 1
        elif raw.startswith("-"):
            rows.append(DiffRow(old_line, None, raw[1:], "deleted"))
            old_line += 1
            deleted += 1
        elif raw.startswith(" "):
            rows.append(DiffRow(old_line, new_line, raw[1:], raw[1:], "context"))
            old_line += 1
            new_line += 1
        elif raw.startswith("\\"):
            continue
    return rows, added_lines, added, deleted


def scan_added_lines(path: str, content_lines: List[str], added_lines: Set[int]) -> List[Finding]:
    findings: List[Finding] = []
    for line_no in sorted(added_lines):
        if line_no < 1 or line_no > len(content_lines):
            continue
        code = content_lines[line_no - 1]
        for rule_id, severity, category, pattern, title, description, recommendation, suggested_test in RULES:
            if pattern.search(code):
                key = f"{path}:{line_no}:{rule_id}"
                findings.append(Finding(
                    id=hashlib.sha1(key.encode("utf-8")).hexdigest()[:12],
                    file=path, line=line_no, severity=severity, category=category,
                    title=title, description=description, recommendation=recommendation,
                    suggested_test=suggested_test, code=code
                ))
    return findings


def call_mcp(config: Dict[str, Any], path: str, diff_text: str) -> List[Finding]:
    mcp = config["mcp"]
    if not mcp.get("enabled") or not mcp.get("server_url"):
        return []
    payload = {
        "jsonrpc": "2.0", "id": f"review-{path}", "method": "tools/call",
        "params": {"name": mcp.get("tool_name", "review_code_diff"), "arguments": {
            "file_path": path, "diff": diff_text, "mode": "read_only", "output": "findings"
        }}
    }
    headers = {"Content-Type": "application/json"}
    if mcp.get("token"):
        headers["Authorization"] = f"Bearer {mcp['token']}"
    try:
        request = urllib.request.Request(mcp["server_url"], data=json.dumps(payload).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
        raw = data.get("result", {}).get("findings", [])
        result = []
        for idx, item in enumerate(raw):
            line = int(item.get("line", item.get("line_number", 1)))
            result.append(Finding(
                id=hashlib.sha1(f"{path}:{line}:mcp:{idx}".encode()).hexdigest()[:12],
                file=path, line=line, severity=str(item.get("severity", "INFO")).upper(),
                category=str(item.get("category", "AI Review")), title=str(item.get("title", "AI recommendation")),
                description=str(item.get("description", "Review the changed code.")),
                recommendation=str(item.get("recommendation", "Review manually.")),
                suggested_test=str(item.get("suggested_test", item.get("suggested_unit_test", ""))),
                code=str(item.get("code", "")), source="mcp-ai"
            ))
        return result
    except Exception as exc:
        print(f"MCP warning for {path}: {exc}", file=sys.stderr)
        return []


def load_history(path: Path) -> List[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(path: Path, entries: List[Dict[str, Any]], max_entries: int) -> None:
    path.write_text(json.dumps(entries[-max_entries:], indent=2), encoding="utf-8")


def assess(findings: List[Finding], config: Dict[str, Any]) -> Tuple[int, str, str, List[str], Dict[str, int]]:
    counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_WEIGHT}
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 1) for f in findings)
    score = max(0, 100 - penalty)
    good = int(config["thresholds"]["good_score"])
    warning = int(config["thresholds"]["warning_score"])
    status = "GOOD" if score >= good else "WARNING" if score >= warning else "FAIL"
    gate = "PASS" if counts["CRITICAL"] <= int(config["thresholds"]["max_critical"]) and counts["HIGH"] <= int(config["thresholds"]["max_high"]) and status != "FAIL" else "FAIL"
    reasons = []
    if counts["CRITICAL"] > int(config["thresholds"]["max_critical"]):
        reasons.append(f"{counts['CRITICAL']} critical finding(s) exceed the allowed maximum.")
    if counts["HIGH"] > int(config["thresholds"]["max_high"]):
        reasons.append(f"{counts['HIGH']} high finding(s) exceed the allowed maximum.")
    if status == "FAIL":
        reasons.append(f"Changed-code score {score} is below {warning}.")
    if not reasons:
        reasons.append("Changed code passed the configured checks.")
    return score, status, gate, reasons, counts


def review(workspace: Path, config: Dict[str, Any], base_arg: Optional[str], head_arg: str) -> ReviewReport:
    if git(workspace, "rev-parse", "--is-inside-work-tree") != "true":
        raise RuntimeError("Workspace is not a Git repository")
    base, head = determine_refs(workspace, base_arg, head_arg)
    files_meta = changed_file_list(workspace, base, head, config)
    changed_files: List[ChangedFile] = []
    all_findings: List[Finding] = []
    total_added = total_deleted = 0
    context = int(config["scan"]["context_lines"])

    for status, path in files_meta:
        diff_text = git(workspace, "diff", f"--unified={context}", "--no-color", base, head, "--", path)
        rows, added_lines, added, deleted = parse_unified_diff(diff_text)
        content = (workspace / path).read_text(encoding="utf-8", errors="replace").splitlines()
        findings = scan_added_lines(path, content, added_lines)
        findings.extend(call_mcp(config, path, diff_text))
        dedup = {(f.file, f.line, f.severity, f.title): f for f in findings}
        findings = sorted(dedup.values(), key=lambda f: (f.line, -SEVERITY_ORDER.get(f.severity, 0)))
        changed_files.append(ChangedFile(path, status, added, deleted, rows, findings))
        all_findings.extend(findings)
        total_added += added
        total_deleted += deleted

    score, status, gate, reasons, counts = assess(all_findings, config)
    commit = git(workspace, "rev-parse", head)
    history_path = workspace / config["history"]["file"]
    history = load_history(history_path)
    entry = {
        "build": os.getenv("BUILD_NUMBER", str(len(history) + 1)),
        "commit": commit[:8], "score": score, "status": status,
        "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    }
    history.append(entry)
    save_history(history_path, history, int(config["history"]["max_entries"]))

    return ReviewReport(
        product=PRODUCT, version=VERSION, generated_at=entry["timestamp"],
        commit=commit, commit_short=commit[:8], commit_message=git(workspace, "log", "-1", "--pretty=%s", head),
        author=git(workspace, "log", "-1", "--pretty=%an", head), base_ref=base, head_ref=head,
        build_number=os.getenv("BUILD_NUMBER", "local"), job_name=os.getenv("JOB_NAME", "local"),
        changed_files=changed_files, counts=counts, total_findings=len(all_findings),
        total_added=total_added, total_deleted=total_deleted, score=score, status=status,
        gate=gate, reasons=reasons, trend=history[-12:]
    )


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def severity_chart(counts: Dict[str, int]) -> str:
    colors = {"CRITICAL": "#d92d20", "HIGH": "#f04438", "MEDIUM": "#f79009", "LOW": "#2e90fa"}
    values = [counts.get(k, 0) for k in colors]
    total = max(sum(values), 1)
    x = 0.0
    blocks = []
    legend = []
    for severity, value in zip(colors, values):
        width = value / total * 100
        if value:
            blocks.append(f'<rect x="{x:.2f}%" y="0" width="{width:.2f}%" height="22" fill="{colors[severity]}"/>')
        x += width
        legend.append(f'<span><i style="background:{colors[severity]}"></i>{severity.title()} <b>{value}</b></span>')
    return f'<svg class="severity-svg" viewBox="0 0 100 22" preserveAspectRatio="none">{"".join(blocks)}</svg><div class="legend">{"".join(legend)}</div>'


def trend_chart(trend: List[Dict[str, Any]]) -> str:
    if not trend:
        return '<div class="empty">No trend data yet.</div>'
    width, height, pad = 640, 190, 26
    usable_w, usable_h = width - 2 * pad, height - 2 * pad
    points = []
    for i, item in enumerate(trend):
        x = pad + (i * usable_w / max(len(trend) - 1, 1))
        y = pad + (100 - int(item.get("score", 0))) * usable_h / 100
        points.append((x, y, item))
    poly = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in points)
    circles = "".join(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4"><title>Build {esc(item.get("build"))}: {esc(item.get("score"))}</title></circle>' for x, y, item in points)
    labels = "".join(f'<text x="{x:.1f}" y="{height-5}" text-anchor="middle">{esc(item.get("build"))}</text>' for x, _, item in points)
    return f'''<svg class="trend" viewBox="0 0 {width} {height}">
      <line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height-pad}"/>
      <line x1="{pad}" y1="{height-pad}" x2="{width-pad}" y2="{height-pad}"/>
      <line class="target" x1="{pad}" y1="{pad+15*usable_h/100}" x2="{width-pad}" y2="{pad+15*usable_h/100}"/>
      <text x="2" y="{pad+4}">100</text><text x="8" y="{height-pad+4}">0</text>
      <polyline points="{poly}"/>{circles}{labels}</svg>'''


def diff_table(file: ChangedFile) -> str:
    findings_by_line: Dict[int, List[Finding]] = {}
    for finding in file.findings:
        findings_by_line.setdefault(finding.line, []).append(finding)
    rows = []
    for row in file.rows:
        findings = findings_by_line.get(row.new_line or -1, [])
        finding_mark = ''.join(f'<span class="pin {f.severity.lower()}" title="{esc(f.title)}">●</span>' for f in findings)
        rows.append(f'''<tr class="{row.kind}">
          <td class="marker">{finding_mark}</td><td class="ln">{row.old_line or ""}</td>
          <td class="old"><code>{esc(row.old_text)}</code></td><td class="ln">{row.new_line or ""}</td>
          <td class="new"><code>{esc(row.new_text)}</code></td></tr>''')
    return f'''<div class="diff-wrap"><table class="diff"><thead><tr><th></th><th>#</th><th>Before</th><th>#</th><th>After</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>'''


def findings_cards(findings: List[Finding]) -> str:
    if not findings:
        return '<div class="clean">No issue found in added lines.</div>'
    cards = []
    for f in findings:
        cards.append(f'''<article class="finding-card {f.severity.lower()}">
          <div class="finding-head"><span class="sev">{esc(f.severity)}</span><b>{esc(f.title)}</b><span>Line {f.line}</span></div>
          <pre><code>{esc(f.code)}</code></pre><p>{esc(f.description)}</p>
          <p><strong>Recommendation:</strong> {esc(f.recommendation)}</p>
          <p><strong>Suggested test:</strong> {esc(f.suggested_test)}</p></article>''')
    return ''.join(cards)


def write_html(report: ReviewReport, output: Path) -> None:
    status_icon = {"GOOD": "✓", "WARNING": "!", "FAIL": "×"}[report.status]
    file_sections = []
    for file in report.changed_files:
        file_sections.append(f'''<section class="file-section">
          <div class="file-head"><div><span class="status-pill">{esc(file.status)}</span><h2>{esc(file.path)}</h2></div>
          <div class="delta"><span class="plus">+{file.added}</span><span class="minus">-{file.deleted}</span><span>{len(file.findings)} finding(s)</span></div></div>
          {diff_table(file)}<div class="findings">{findings_cards(file.findings)}</div></section>''')
    if not file_sections:
        file_sections.append('<section class="panel"><h2>No reviewable changed files</h2><p>The commit contains no supported source-file changes.</p></section>')

    doc = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(report.product)}</title><style>
:root{{--bg:#f2f4f7;--card:#fff;--ink:#101828;--muted:#667085;--line:#e4e7ec;--green:#12b76a;--red:#d92d20;--amber:#f79009;--blue:#175cd3}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif}}.top{{padding:28px;background:linear-gradient(135deg,#101828,#344054);color:white}}.top-inner,.container{{max-width:1440px;margin:auto}}.top h1{{margin:0 0 6px;font-size:26px}}.top p{{margin:0;color:#d0d5dd}}.container{{padding:22px}}.hero{{display:grid;grid-template-columns:260px 1fr;gap:18px;margin-top:-8px}}.status-card,.panel,.file-section,.metric{{background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 3px 12px #1018280d}}.status-card{{padding:22px;text-align:center}}.status-icon{{width:86px;height:86px;margin:auto;border-radius:50%;display:grid;place-items:center;font-size:54px;font-weight:700;color:white;background:{'#12b76a' if report.status=='GOOD' else '#f79009' if report.status=='WARNING' else '#d92d20'}}}.status-card h2{{margin:12px 0 4px}}.gauge{{height:10px;background:#eaecf0;border-radius:10px;overflow:hidden;margin:15px 0 5px}}.gauge i{{display:block;height:100%;width:{report.score}%;background:linear-gradient(90deg,#d92d20,#f79009 55%,#12b76a)}}.score{{font-size:28px;font-weight:800}}.meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.metric{{padding:16px}}.metric span{{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}}.metric b{{display:block;margin-top:7px;font-size:20px;overflow-wrap:anywhere}}.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin:18px 0}}.panel{{padding:18px}}.panel h2{{margin:0 0 14px;font-size:18px}}.severity-svg{{width:100%;height:22px;border-radius:6px;background:#eaecf0}}.legend{{display:flex;gap:16px;flex-wrap:wrap;margin-top:14px;color:var(--muted)}}.legend i{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}}.trend{{width:100%;height:190px}}.trend line{{stroke:#d0d5dd}}.trend .target{{stroke:#12b76a;stroke-dasharray:6 5}}.trend polyline{{fill:none;stroke:#175cd3;stroke-width:4}}.trend circle{{fill:#fff;stroke:#175cd3;stroke-width:3}}.trend text{{font-size:10px;fill:#667085}}.reasons{{margin:0;padding-left:20px}}.file-section{{margin:18px 0;overflow:hidden}}.file-head{{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line)}}.file-head h2{{display:inline;margin:0 0 0 8px;font-size:17px}}.status-pill{{display:inline-block;padding:3px 8px;border-radius:20px;background:#eef4ff;color:#3538cd;font-size:11px;font-weight:700}}.delta{{display:flex;gap:12px;color:var(--muted)}}.plus{{color:#067647}}.minus{{color:#b42318}}.diff-wrap{{overflow:auto}}.diff{{width:100%;border-collapse:collapse;table-layout:fixed}}.diff th{{background:#f9fafb;color:var(--muted);font-size:12px;text-align:left;padding:10px;border-bottom:1px solid var(--line)}}.diff td{{padding:5px 8px;vertical-align:top;border-bottom:1px solid #f2f4f7}}.diff .marker{{width:38px}}.diff .ln{{width:54px;color:#98a2b3;text-align:right;user-select:none}}.diff .old,.diff .new{{width:calc(50% - 73px)}}.diff code{{white-space:pre-wrap;word-break:break-word;font-family:Consolas,monospace;font-size:12px}}.diff tr.added .new{{background:#ecfdf3}}.diff tr.deleted .old{{background:#fef3f2}}.pin{{font-size:18px;margin-right:3px}}.pin.critical,.pin.high{{color:#d92d20}}.pin.medium{{color:#f79009}}.pin.low{{color:#2e90fa}}.findings{{padding:16px;background:#fcfcfd}}.finding-card{{background:white;border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:10px;padding:13px;margin:10px 0}}.finding-card.critical,.finding-card.high{{border-left-color:#d92d20}}.finding-card.medium{{border-left-color:#f79009}}.finding-card.low{{border-left-color:#2e90fa}}.finding-head{{display:flex;gap:10px;align-items:center}}.finding-head span:last-child{{margin-left:auto;color:var(--muted)}}.sev{{font-size:10px;font-weight:800;padding:3px 7px;border-radius:10px;background:#f2f4f7}}.finding-card pre{{background:#101828;color:#e4e7ec;padding:10px;border-radius:8px;overflow:auto}}.clean{{padding:14px;background:#ecfdf3;color:#067647;border-radius:10px}}.footer{{text-align:center;color:var(--muted);font-size:12px;padding:20px}}@media(max-width:850px){{.hero,.grid2{{grid-template-columns:1fr}}.meta{{grid-template-columns:1fr 1fr}}}}
</style></head><body><header class="top"><div class="top-inner"><h1>{esc(report.product)} <small>v{esc(report.version)}</small></h1><p>Changed-code review for commit {esc(report.commit_short)}</p></div></header><main class="container">
<section class="hero"><div class="status-card"><div class="status-icon">{status_icon}</div><h2>{esc(report.status)}</h2><div class="gauge"><i></i></div><div class="score">{report.score}/100</div><p>Quality gate: <strong>{esc(report.gate)}</strong></p></div>
<div class="meta"><div class="metric"><span>Commit</span><b>{esc(report.commit_short)}</b><small>{esc(report.commit_message)}</small></div><div class="metric"><span>Author</span><b>{esc(report.author)}</b></div><div class="metric"><span>Changed files</span><b>{len(report.changed_files)}</b></div><div class="metric"><span>Code delta</span><b><i class="plus">+{report.total_added}</i> <i class="minus">-{report.total_deleted}</i></b></div><div class="metric"><span>Total findings</span><b>{report.total_findings}</b></div><div class="metric"><span>Build</span><b>{esc(report.build_number)}</b></div><div class="metric"><span>Base</span><b>{esc(report.base_ref)}</b></div><div class="metric"><span>Head</span><b>{esc(report.head_ref)}</b></div></div></section>
<div class="grid2"><section class="panel"><h2>Severity distribution</h2>{severity_chart(report.counts)}</section><section class="panel"><h2>Changed-code score trend</h2>{trend_chart(report.trend)}</section></div>
<section class="panel"><h2>Decision reasons</h2><ul class="reasons">{''.join(f'<li>{esc(r)}</li>' for r in report.reasons)}</ul></section>
{''.join(file_sections)}<div class="footer">Generated {esc(report.generated_at)}. Read-only analysis. Only supported files changed between {esc(report.base_ref)} and {esc(report.head_ref)} were reviewed.</div></main></body></html>'''
    output.write_text(doc, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Changed-code AI reviewer for Jenkins")
    parser.add_argument("--workspace", default=os.getenv("WORKSPACE", "."))
    parser.add_argument("--config", default="")
    parser.add_argument("--base", default="", help="Optional base Git ref/commit")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--html-output", default="ai_code_review_report.html")
    parser.add_argument("--json-output", default="ai_code_review_report.json")
    parser.add_argument("--fail-build", default="false")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace).resolve()
    config = load_config(args.config or None)
    report = review(workspace, config, args.base or None, args.head)
    (workspace / args.json_output).write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")
    write_html(report, workspace / args.html_output)
    print("=" * 72)
    print(f"{PRODUCT} v{VERSION}")
    print(f"Commit: {report.commit_short} | Changed files: {len(report.changed_files)}")
    print(f"Status: {report.status} | Gate: {report.gate} | Score: {report.score}/100")
    print(f"Findings: {report.total_findings} | +{report.total_added} -{report.total_deleted}")
    for reason in report.reasons:
        print(f"- {reason}")
    print("=" * 72)
    if str(args.fail_build).lower() in {"1", "true", "yes"} and report.gate == "FAIL":
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"AI Code Reviewer failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
