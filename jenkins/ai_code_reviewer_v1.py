#!/usr/bin/env python3
"""
AI Code Reviewer for Jenkins - Version 1

Purpose:
- Jenkins-ready Python based code reviewer
- Scans a workspace during build
- Shows red markers on exact lines in HTML report
- Gives recommendations and suggested unit tests
- Calculates code score, build score, and release readiness score
- Produces quality gate PASS / FAIL
- Generates JSON + HTML reports for Jenkins artifacts
- Includes MCP server placeholder for future integration
- Read-only: never modifies source code

Python 3.8+
No external pip packages required.
"""

import argparse
import datetime as dt
import fnmatch
import html
import json
import os
import re
import statistics
import subprocess
import sys
import traceback
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PRODUCT_NAME = "AI Code Reviewer for Jenkins"
PRODUCT_VERSION = "1.0.0"

SUPPORTED_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".tsx", ".jsx", ".c", ".cpp", ".h", ".hpp",
    ".cs", ".go", ".rs", ".sh", ".bat", ".ps1", ".yaml", ".yml", ".json",
    ".xml", ".gradle", ".groovy"
}
SUPPORTED_SPECIAL_FILES = {"Dockerfile", "Jenkinsfile"}
EXCLUDED_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "dist", "build", "target", "venv", ".venv",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".idea", ".vscode", ".tox"
}

DEFAULT_CONFIG = {
    "thresholds": {
        "min_code_score": 75,
        "min_build_score": 75,
        "min_release_readiness_score": 75,
        "max_critical_findings": 0,
        "max_high_findings": 5,
        "min_coverage_percent": 60.0,
        "max_test_failure_rate_percent": 10.0
    },
    "mcp": {
        "server_url": "",
        "token": "",
        "tool_name": "review_code",
        "enabled": False
    },
    "scan": {
        "max_file_size_kb": 512
    }
}


@dataclass
class Finding:
    finding_id: str
    file_path: str
    line_number: int
    severity: str
    category: str
    title: str
    description: str
    recommendation: str
    suggested_unit_test: str
    source: str = "local-rule"


@dataclass
class FileReview:
    file_path: str
    has_red_marker: bool
    finding_count: int
    highest_severity: str
    findings: List[Finding] = field(default_factory=list)
    code_lines: List[str] = field(default_factory=list)


@dataclass
class TestSummary:
    total: int = 0
    failures: int = 0
    errors: int = 0
    skipped: int = 0
    duration_seconds: float = 0.0

    @property
    def failed_total(self) -> int:
        return self.failures + self.errors

    @property
    def failure_rate_percent(self) -> float:
        if self.total <= 0:
            return 0.0
        return round((self.failed_total / self.total) * 100.0, 2)


@dataclass
class CoverageSummary:
    coverage_percent: Optional[float] = None
    source: str = "not_found"


@dataclass
class Scores:
    code_score: int
    build_score: int
    release_readiness_score: int
    quality_gate: str
    reasons: List[str]


@dataclass
class GitSummary:
    branch: str = "unknown"
    commit: str = "unknown"
    commit_short: str = "unknown"
    changed_files: int = 0
    changed_lines_total: int = 0


@dataclass
class ReviewReport:
    product: str
    version: str
    generated_at_utc: str
    workspace: str
    jenkins: Dict[str, str]
    git: GitSummary
    tests: TestSummary
    coverage: CoverageSummary
    scores: Scores
    total_files_scanned: int
    files_with_red_marker: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    files: List[FileReview]


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def severity_rank(severity: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(severity.upper(), 0)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def safe_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled"}:
        return False
    return default


def run_cmd(command: List[str], cwd: str, timeout: int = 20) -> Tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace"
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 1, "", str(exc)


def load_config(config_path: Optional[str]) -> Dict[str, Any]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if config_path and Path(config_path).exists():
        user_config = json.loads(Path(config_path).read_text(encoding="utf-8"))
        config = deep_merge(config, user_config)

    env_mcp_url = os.getenv("MCP_SERVER_URL")
    if env_mcp_url:
        config["mcp"]["server_url"] = env_mcp_url
        config["mcp"]["enabled"] = True

    env_mcp_token = os.getenv("MCP_TOKEN")
    if env_mcp_token:
        config["mcp"]["token"] = env_mcp_token

    return config


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    output = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = deep_merge(output[key], value)
        else:
            output[key] = value
    return output


def is_supported_file(path: Path) -> bool:
    return path.name in SUPPORTED_SPECIAL_FILES or path.suffix in SUPPORTED_EXTENSIONS


def collect_files(workspace: Path, max_file_size_kb: int) -> List[Path]:
    files: List[Path] = []
    max_bytes = max_file_size_kb * 1024
    for root, dirs, names in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for name in names:
            path = Path(root) / name
            try:
                if is_supported_file(path) and path.stat().st_size <= max_bytes:
                    files.append(path)
            except Exception:
                continue
    return files


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


class LocalRuleReviewer:
    RULES = [
        {
            "id": "SECRET001",
            "severity": "CRITICAL",
            "category": "Security",
            "pattern": re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
            "title": "Possible hardcoded secret",
            "description": "A password, token, secret, or API key appears to be hardcoded.",
            "recommendation": "Move secrets to Jenkins credentials, environment variables, or a secure vault.",
            "unit_test": "Add a CI test that fails when secrets are committed in source files."
        },
        {
            "id": "SEC101",
            "severity": "HIGH",
            "category": "Security",
            "pattern": re.compile(r"\beval\s*\("),
            "title": "Unsafe eval usage",
            "description": "eval() can execute arbitrary code and may create a security risk.",
            "recommendation": "Avoid eval(). Use safe parsing, explicit mapping, or ast.literal_eval for simple literals.",
            "unit_test": "Add a malicious-input test and verify the code rejects it safely."
        },
        {
            "id": "SEC102",
            "severity": "HIGH",
            "category": "Security",
            "pattern": re.compile(r"\bexec\s*\("),
            "title": "Unsafe exec usage",
            "description": "exec() can execute dynamic code and may be dangerous.",
            "recommendation": "Avoid exec(). Replace it with explicit function calls or controlled command mapping.",
            "unit_test": "Add tests proving unexpected input cannot trigger code execution."
        },
        {
            "id": "SEC103",
            "severity": "HIGH",
            "category": "Security",
            "pattern": re.compile(r"shell\s*=\s*True"),
            "title": "shell=True detected",
            "description": "Using shell=True can allow command injection if user input reaches the command.",
            "recommendation": "Pass command arguments as a list and keep shell=False.",
            "unit_test": "Add a test with shell special characters and verify injection is not possible."
        },
        {
            "id": "ERR101",
            "severity": "MEDIUM",
            "category": "Reliability",
            "pattern": re.compile(r"except\s*:\s*$"),
            "title": "Bare except detected",
            "description": "Bare except hides real errors and makes debugging difficult.",
            "recommendation": "Catch specific exception types and log useful error information.",
            "unit_test": "Add a test that triggers the expected exception and verifies the handling path."
        },
        {
            "id": "TODO101",
            "severity": "LOW",
            "category": "Maintainability",
            "pattern": re.compile(r"(?i)\b(todo|fixme|hack|temporary workaround)\b"),
            "title": "TODO or FIXME found",
            "description": "Temporary or unfinished work is present in the code.",
            "recommendation": "Convert this into a tracked task or complete the implementation.",
            "unit_test": "Add a test that covers the incomplete behavior before closing the TODO."
        },
        {
            "id": "DBG101",
            "severity": "LOW",
            "category": "Maintainability",
            "pattern": re.compile(r"\bprint\s*\(|console\.log\s*\("),
            "title": "Debug output found",
            "description": "Debug output may create noise in production logs.",
            "recommendation": "Use structured logging instead of print or console.log.",
            "unit_test": "Add a test to verify important events are logged through a logger."
        }
    ]

    def review(self, file_path: Path, relative_path: str, content: str) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.splitlines()
        for index, line in enumerate(lines, start=1):
            for rule in self.RULES:
                if rule["pattern"].search(line):
                    findings.append(Finding(
                        finding_id=f"{relative_path}:{index}:{rule['id']}",
                        file_path=relative_path,
                        line_number=index,
                        severity=rule["severity"],
                        category=rule["category"],
                        title=rule["title"],
                        description=rule["description"],
                        recommendation=rule["recommendation"],
                        suggested_unit_test=rule["unit_test"],
                        source="local-rule"
                    ))
        if len(lines) > 800:
            findings.append(Finding(
                finding_id=f"{relative_path}:1:SIZE101",
                file_path=relative_path,
                line_number=1,
                severity="MEDIUM",
                category="Maintainability",
                title="Large file detected",
                description=f"This file has {len(lines)} lines and may be difficult to maintain.",
                recommendation="Consider splitting this file into smaller focused modules.",
                suggested_unit_test="Add regression tests before refactoring this file.",
                source="local-rule"
            ))
        complexity = rough_complexity(lines)
        if complexity >= 80:
            findings.append(Finding(
                finding_id=f"{relative_path}:1:CPLX101",
                file_path=relative_path,
                line_number=1,
                severity="MEDIUM",
                category="Maintainability",
                title="High complexity detected",
                description=f"Rough complexity score is {complexity}.",
                recommendation="Reduce nested logic and split complex code into smaller functions.",
                suggested_unit_test="Add branch and boundary tests before simplifying this logic.",
                source="local-rule"
            ))
        return findings


def rough_complexity(lines: List[str]) -> int:
    tokens = [r"\bif\b", r"\belif\b", r"\bfor\b", r"\bwhile\b", r"\bcase\b", r"\bcatch\b", r"\bexcept\b", r"\bswitch\b"]
    score = 0
    for line in lines:
        stripped = line.strip()
        for token in tokens:
            if re.search(token, stripped):
                score += 1
        indent = (len(line) - len(line.lstrip(" "))) // 4
        if indent >= 4:
            score += 1
    return score


class MCPReviewer:
    """
    MCP placeholder.
    Add your MCP server URL in config or env variable MCP_SERVER_URL.
    Expected MCP tool: review_code.
    This function is safe: if server is empty/unavailable it simply returns no MCP findings.
    """
    def __init__(self, config: Dict[str, Any]):
        self.enabled = bool_value(config["mcp"].get("enabled"), False)
        self.server_url = config["mcp"].get("server_url", "")
        self.token = config["mcp"].get("token", "")
        self.tool_name = config["mcp"].get("tool_name", "review_code")

    def review(self, relative_path: str, content: str) -> List[Finding]:
        if not self.enabled or not self.server_url:
            return []
        payload = {
            "jsonrpc": "2.0",
            "id": f"review-{relative_path}",
            "method": "tools/call",
            "params": {
                "name": self.tool_name,
                "arguments": {
                    "file_path": relative_path,
                    "file_content": content,
                    "mode": "read_only",
                    "output": "findings"
                }
            }
        }
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            request = urllib.request.Request(
                self.server_url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
            return parse_mcp_findings(data, relative_path)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, Exception) as exc:
            print(f"[MCP warning] {relative_path}: {exc}", file=sys.stderr)
            return []


def parse_mcp_findings(data: Dict[str, Any], relative_path: str) -> List[Finding]:
    raw: List[Dict[str, Any]] = []
    result = data.get("result", {}) if isinstance(data, dict) else {}
    if isinstance(result, dict) and isinstance(result.get("findings"), list):
        raw = result["findings"]
    elif isinstance(result, dict) and isinstance(result.get("content"), list):
        for item in result["content"]:
            if isinstance(item, dict) and isinstance(item.get("json"), dict) and isinstance(item["json"].get("findings"), list):
                raw.extend(item["json"]["findings"])
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                try:
                    parsed = json.loads(item["text"])
                    if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
                        raw.extend(parsed["findings"])
                except Exception:
                    pass
    findings: List[Finding] = []
    for idx, item in enumerate(raw, start=1):
        line = safe_int(item.get("line_number", item.get("line", 1)), 1)
        severity = str(item.get("severity", "INFO")).upper()
        findings.append(Finding(
            finding_id=f"{relative_path}:{line}:MCP{idx}",
            file_path=relative_path,
            line_number=line,
            severity=severity,
            category=str(item.get("category", "AI Review")),
            title=str(item.get("title", "AI recommendation")),
            description=str(item.get("description", "AI reviewer found a possible improvement.")),
            recommendation=str(item.get("recommendation", "Review this code manually.")),
            suggested_unit_test=str(item.get("suggested_unit_test", "")),
            source="mcp-ai-reviewer"
        ))
    return findings


def parse_junit(workspace: Path, pattern: Optional[str]) -> TestSummary:
    summary = TestSummary()
    if not pattern:
        return summary
    matched: List[Path] = []
    for root, _, files in os.walk(workspace):
        for name in files:
            full = Path(root) / name
            rel = str(full.relative_to(workspace))
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(str(full), pattern):
                matched.append(full)
    for file_path in matched:
        try:
            root = ET.parse(file_path).getroot()
            suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite")) or list(root.iter("testsuite"))
            for suite in suites:
                summary.total += safe_int(suite.attrib.get("tests"), 0)
                summary.failures += safe_int(suite.attrib.get("failures"), 0)
                summary.errors += safe_int(suite.attrib.get("errors"), 0)
                summary.skipped += safe_int(suite.attrib.get("skipped"), 0)
                summary.duration_seconds += safe_float(suite.attrib.get("time"), 0.0) or 0.0
        except Exception:
            continue
    summary.duration_seconds = round(summary.duration_seconds, 2)
    return summary


def parse_coverage(workspace: Path, coverage_file: Optional[str]) -> CoverageSummary:
    if not coverage_file:
        return CoverageSummary(None, "not_configured")
    path = Path(coverage_file)
    if not path.is_absolute():
        path = workspace / coverage_file
    if not path.exists():
        return CoverageSummary(None, "not_found")
    try:
        if path.suffix.lower() == ".xml":
            root = ET.parse(path).getroot()
            line_rate = root.attrib.get("line-rate")
            if line_rate is not None:
                return CoverageSummary(round(float(line_rate) * 100.0, 2), path.name)
            covered = 0
            missed = 0
            for counter in root.iter("counter"):
                if counter.attrib.get("type") in {"LINE", "INSTRUCTION"}:
                    covered += safe_int(counter.attrib.get("covered"), 0)
                    missed += safe_int(counter.attrib.get("missed"), 0)
            if covered + missed > 0:
                return CoverageSummary(round((covered / (covered + missed)) * 100.0, 2), path.name)
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            totals = data.get("totals", {})
            if "percent_covered" in totals:
                return CoverageSummary(round(float(totals["percent_covered"]), 2), path.name)
            if "coverage_percent" in data:
                return CoverageSummary(round(float(data["coverage_percent"]), 2), path.name)
    except Exception:
        return CoverageSummary(None, "parse_error")
    return CoverageSummary(None, "unsupported_format")


def git_summary(workspace: Path) -> GitSummary:
    code, out, _ = run_cmd(["git", "rev-parse", "--is-inside-work-tree"], cwd=str(workspace))
    if code != 0 or out.strip() != "true":
        return GitSummary()
    branch = git_out(workspace, ["git", "rev-parse", "--abbrev-ref", "HEAD"], "unknown")
    commit = git_out(workspace, ["git", "rev-parse", "HEAD"], "unknown")
    changed_files, changed_lines = git_diff_stats(workspace)
    return GitSummary(
        branch=branch,
        commit=commit,
        commit_short=commit[:8] if commit != "unknown" else "unknown",
        changed_files=changed_files,
        changed_lines_total=changed_lines
    )


def git_out(workspace: Path, command: List[str], default: str) -> str:
    code, out, _ = run_cmd(command, cwd=str(workspace))
    return out if code == 0 and out else default


def git_diff_stats(workspace: Path) -> Tuple[int, int]:
    base_ref = os.getenv("CHANGE_TARGET") or os.getenv("GIT_PREVIOUS_SUCCESSFUL_COMMIT")
    command = ["git", "diff", "--numstat", f"{base_ref}..HEAD"] if base_ref else ["git", "diff", "--numstat", "HEAD~1..HEAD"]
    code, out, _ = run_cmd(command, cwd=str(workspace))
    if code != 0 or not out:
        return 0, 0
    files = 0
    lines = 0
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            files += 1
            lines += safe_int(parts[0], 0) + safe_int(parts[1], 0)
    return files, lines


def score_report(findings: List[Finding], tests: TestSummary, coverage: CoverageSummary, config: Dict[str, Any]) -> Scores:
    thresholds = config["thresholds"]
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    code_penalty = critical * 25 + high * 10 + medium * 4 + low * 1
    code_score = max(0, min(100, 100 - code_penalty))

    build_penalty = 0
    build_penalty += min(60, tests.failure_rate_percent * 4)
    if coverage.coverage_percent is not None:
        if coverage.coverage_percent < thresholds["min_coverage_percent"]:
            build_penalty += min(40, (thresholds["min_coverage_percent"] - coverage.coverage_percent) * 1.5)
    build_score = int(max(0, min(100, round(100 - build_penalty))))

    release_readiness_score = int(round((code_score * 0.55) + (build_score * 0.45)))

    reasons: List[str] = []
    gate = "PASS"
    checks = [
        (code_score < thresholds["min_code_score"], f"Code score {code_score} is below threshold {thresholds['min_code_score']}"),
        (build_score < thresholds["min_build_score"], f"Build score {build_score} is below threshold {thresholds['min_build_score']}"),
        (release_readiness_score < thresholds["min_release_readiness_score"], f"Release readiness score {release_readiness_score} is below threshold {thresholds['min_release_readiness_score']}"),
        (critical > thresholds["max_critical_findings"], f"Critical findings {critical} exceed threshold {thresholds['max_critical_findings']}"),
        (high > thresholds["max_high_findings"], f"High findings {high} exceed threshold {thresholds['max_high_findings']}"),
        (tests.failure_rate_percent > thresholds["max_test_failure_rate_percent"], f"Test failure rate {tests.failure_rate_percent}% exceeds threshold {thresholds['max_test_failure_rate_percent']}%"),
        (coverage.coverage_percent is not None and coverage.coverage_percent < thresholds["min_coverage_percent"], f"Coverage {coverage.coverage_percent}% is below threshold {thresholds['min_coverage_percent']}%")
    ]
    for failed, reason in checks:
        if failed:
            gate = "FAIL"
            reasons.append(reason)
    if not reasons:
        reasons.append("All Version 1 quality checks passed.")

    return Scores(code_score, build_score, release_readiness_score, gate, reasons)


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.file_path, f.line_number, f.severity, f.title, f.recommendation)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def build_report(workspace: Path, args: argparse.Namespace, config: Dict[str, Any]) -> ReviewReport:
    local = LocalRuleReviewer()
    mcp = MCPReviewer(config)
    files = collect_files(workspace, safe_int(config["scan"].get("max_file_size_kb"), 512))
    file_reviews: List[FileReview] = []
    all_findings: List[Finding] = []

    for file_path in files:
        rel = str(file_path.relative_to(workspace))
        content = read_text(file_path)
        code_lines = content.splitlines()
        findings = []
        findings.extend(local.review(file_path, rel, content))
        findings.extend(mcp.review(rel, content))
        findings = dedupe_findings(findings)
        all_findings.extend(findings)
        highest = "INFO"
        if findings:
            highest = max([f.severity for f in findings], key=severity_rank)
        file_reviews.append(FileReview(
            file_path=rel,
            has_red_marker=bool(findings),
            finding_count=len(findings),
            highest_severity=highest,
            findings=findings,
            code_lines=code_lines
        ))

    tests = parse_junit(workspace, args.junit_pattern)
    coverage = parse_coverage(workspace, args.coverage_file)
    scores = score_report(all_findings, tests, coverage, config)
    git = git_summary(workspace)
    jenkins = {
        "JOB_NAME": os.getenv("JOB_NAME", "local-job"),
        "BUILD_NUMBER": os.getenv("BUILD_NUMBER", "local-build"),
        "BUILD_URL": os.getenv("BUILD_URL", ""),
        "BRANCH_NAME": os.getenv("BRANCH_NAME", "")
    }
    return ReviewReport(
        product=PRODUCT_NAME,
        version=PRODUCT_VERSION,
        generated_at_utc=now_utc(),
        workspace=str(workspace),
        jenkins=jenkins,
        git=git,
        tests=tests,
        coverage=coverage,
        scores=scores,
        total_files_scanned=len(files),
        files_with_red_marker=sum(1 for fr in file_reviews if fr.has_red_marker),
        total_findings=len(all_findings),
        critical_count=sum(1 for f in all_findings if f.severity == "CRITICAL"),
        high_count=sum(1 for f in all_findings if f.severity == "HIGH"),
        medium_count=sum(1 for f in all_findings if f.severity == "MEDIUM"),
        low_count=sum(1 for f in all_findings if f.severity == "LOW"),
        files=file_reviews
    )


def write_json(report: ReviewReport, output_path: Path) -> None:
    output_path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def severity_class(severity: str) -> str:
    return severity.lower() if severity.lower() in {"critical", "high", "medium", "low"} else "info"


def write_html(report: ReviewReport, output_path: Path) -> None:
    file_sections = []
    for file_review in report.files:
        if not file_review.findings:
            continue
        findings_by_line: Dict[int, List[Finding]] = {}
        for finding in file_review.findings:
            findings_by_line.setdefault(finding.line_number, []).append(finding)

        line_rows = []
        start_lines = sorted(findings_by_line.keys())
        for line_no in start_lines:
            line_text = ""
            if 1 <= line_no <= len(file_review.code_lines):
                line_text = file_review.code_lines[line_no - 1]
            for finding in findings_by_line[line_no]:
                line_rows.append(f"""
                <tr class="issue-row">
                    <td class="red-cell">🔴</td>
                    <td class="line-no">{line_no}</td>
                    <td><pre>{html.escape(line_text)}</pre></td>
                    <td><span class="badge {severity_class(finding.severity)}">{html.escape(finding.severity)}</span></td>
                    <td>
                        <b>{html.escape(finding.title)}</b><br>
                        <span>{html.escape(finding.description)}</span><br><br>
                        <b>Recommendation:</b> {html.escape(finding.recommendation)}<br>
                        <b>Suggested Unit Test:</b> {html.escape(finding.suggested_unit_test)}<br>
                        <small>Source: {html.escape(finding.source)}</small>
                    </td>
                </tr>
                """)
        file_sections.append(f"""
        <section class="file-card">
            <h2>🔴 {html.escape(file_review.file_path)} <span class="small">{file_review.finding_count} recommendation(s)</span></h2>
            <table>
                <thead><tr><th></th><th>Line</th><th>Code</th><th>Severity</th><th>AI Code Review</th></tr></thead>
                <tbody>{''.join(line_rows)}</tbody>
            </table>
        </section>
        """)

    html_doc = f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(report.product)} Report</title>
<style>
body {{ margin: 0; font-family: Arial, sans-serif; background: #f4f6fb; color: #1f2937; }}
.header {{ background: #111827; color: white; padding: 24px; }}
.header h1 {{ margin: 0; }}
.container {{ padding: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 18px; }}
.card {{ background: white; border-radius: 16px; padding: 16px; box-shadow: 0 5px 18px rgba(15,23,42,.08); }}
.label {{ color: #6b7280; font-size: 13px; }}
.value {{ font-size: 30px; font-weight: 800; margin-top: 6px; }}
.pass {{ color: #047857; }} .fail {{ color: #b91c1c; }}
.file-card {{ background: white; border-radius: 16px; padding: 16px; margin: 18px 0; box-shadow: 0 5px 18px rgba(15,23,42,.08); }}
.small {{ font-size: 13px; color: #6b7280; font-weight: normal; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ border-bottom: 1px solid #e5e7eb; padding: 10px; vertical-align: top; font-size: 13px; }}
th {{ background: #f3f4f6; text-align: left; }}
pre {{ margin: 0; white-space: pre-wrap; font-family: Consolas, monospace; font-size: 12px; }}
.red-cell {{ font-size: 18px; width: 32px; }}
.line-no {{ color: #6b7280; width: 60px; }}
.badge {{ color: white; padding: 4px 8px; border-radius: 999px; font-weight: bold; font-size: 11px; }}
.critical {{ background: #991b1b; }} .high {{ background: #dc2626; }} .medium {{ background: #f59e0b; }} .low {{ background: #2563eb; }} .info {{ background: #6b7280; }}
.reasons li {{ margin-bottom: 6px; }}
.footer {{ color: #6b7280; font-size: 12px; margin-top: 24px; }}
</style>
</head>
<body>
<div class="header">
    <h1>{html.escape(report.product)} v{html.escape(report.version)}</h1>
    <p>Jenkins-ready read-only AI code review. Red markers show exact lines needing review.</p>
</div>
<div class="container">
    <div class="grid">
        <div class="card"><div class="label">Quality Gate</div><div class="value {'pass' if report.scores.quality_gate == 'PASS' else 'fail'}">{report.scores.quality_gate}</div></div>
        <div class="card"><div class="label">Code Score</div><div class="value">{report.scores.code_score}</div></div>
        <div class="card"><div class="label">Build Score</div><div class="value">{report.scores.build_score}</div></div>
        <div class="card"><div class="label">Release Readiness</div><div class="value">{report.scores.release_readiness_score}</div></div>
    </div>
    <div class="grid">
        <div class="card"><div class="label">Files Scanned</div><div class="value">{report.total_files_scanned}</div></div>
        <div class="card"><div class="label">Files with Red Marker</div><div class="value">{report.files_with_red_marker}</div></div>
        <div class="card"><div class="label">Total Recommendations</div><div class="value">{report.total_findings}</div></div>
        <div class="card"><div class="label">Coverage</div><div class="value">{report.coverage.coverage_percent if report.coverage.coverage_percent is not None else 'N/A'}%</div></div>
    </div>
    <div class="card">
        <h2>Gate Reasons</h2>
        <ul class="reasons">{''.join(f'<li>{html.escape(r)}</li>' for r in report.scores.reasons)}</ul>
    </div>
    <div class="card">
        <h2>Build Test Summary</h2>
        <p><b>Tests:</b> {report.tests.total} | <b>Failures/Errors:</b> {report.tests.failed_total} | <b>Failure Rate:</b> {report.tests.failure_rate_percent}% | <b>Skipped:</b> {report.tests.skipped}</p>
        <p><b>Git:</b> branch {html.escape(report.git.branch)}, commit {html.escape(report.git.commit_short)}, changed files {report.git.changed_files}, changed lines {report.git.changed_lines_total}</p>
    </div>
    {''.join(file_sections) if file_sections else '<div class="card"><h2>No red markers</h2><p>No recommendations were found.</p></div>'}
    <div class="footer">Generated at {html.escape(report.generated_at_utc)}. This tool is read-only and does not modify code.</div>
</div>
</body>
</html>"""
    output_path.write_text(html_doc, encoding="utf-8")


def print_summary(report: ReviewReport) -> None:
    print("\n" + "=" * 80)
    print(f"{report.product} v{report.version}")
    print("=" * 80)
    print(f"Quality Gate          : {report.scores.quality_gate}")
    print(f"Code Score            : {report.scores.code_score}")
    print(f"Build Score           : {report.scores.build_score}")
    print(f"Release Readiness     : {report.scores.release_readiness_score}")
    print(f"Files Scanned         : {report.total_files_scanned}")
    print(f"Files with Red Marker : {report.files_with_red_marker}")
    print(f"Total Recommendations : {report.total_findings}")
    print(f"Critical              : {report.critical_count}")
    print(f"High                  : {report.high_count}")
    print(f"Medium                : {report.medium_count}")
    print(f"Low                   : {report.low_count}")
    print("Reasons:")
    for reason in report.scores.reasons:
        print(f"- {reason}")
    print("=" * 80 + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Code Reviewer for Jenkins - Version 1")
    parser.add_argument("--workspace", default=os.getenv("WORKSPACE", os.getcwd()), help="Workspace folder to scan")
    parser.add_argument("--config", default="", help="Optional config JSON")
    parser.add_argument("--coverage-file", default=os.getenv("COVERAGE_FILE", ""), help="Coverage XML or JSON file")
    parser.add_argument("--junit-pattern", default=os.getenv("JUNIT_PATTERN", ""), help="JUnit XML glob pattern, example reports\\TEST-*.xml")
    parser.add_argument("--html-output", default="ai_code_review_report.html", help="HTML report output")
    parser.add_argument("--json-output", default="ai_code_review_report.json", help="JSON report output")
    parser.add_argument("--fail-build", default="false", help="true to exit 2 when quality gate fails")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workspace = Path(args.workspace).resolve()
    if not workspace.exists():
        print(f"Workspace does not exist: {workspace}", file=sys.stderr)
        return 1
    config = load_config(args.config or None)
    report = build_report(workspace, args, config)
    html_path = workspace / args.html_output
    json_path = workspace / args.json_output
    write_html(report, html_path)
    write_json(report, json_path)
    print_summary(report)
    print(f"HTML report: {html_path}")
    print(f"JSON report: {json_path}")
    if bool_value(args.fail_build, False) and report.scores.quality_gate == "FAIL":
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Fatal error in AI Code Reviewer", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
