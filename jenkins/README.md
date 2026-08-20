# AI Code Reviewer for Jenkins - Version 1

This is a Python-only Jenkins-ready AI Code Reviewer prototype.

## Features

- Workspace scanner
- Local rule-based code review
- Red markers in HTML report on exact lines
- Recommendation and suggested unit test for each issue
- Code score
- Build score
- Release readiness score
- Quality gate PASS / FAIL
- JUnit XML parsing
- Coverage XML/JSON parsing
- Git summary
- MCP server placeholder
- Jenkinsfile example
- Read-only behavior: never changes code

## Run locally

```powershell
python ai_code_reviewer_v1.py --workspace . --config ai_code_reviewer_config.json --fail-build false
```

With coverage and JUnit:

```powershell
python ai_code_reviewer_v1.py `
  --workspace . `
  --config ai_code_reviewer_config.json `
  --coverage-file coverage.xml `
  --junit-pattern "reports\TEST-*.xml" `
  --fail-build false
```

Open report:

```powershell
start ai_code_review_report.html
```

## Jenkins

Copy these files into your repo:

- ai_code_reviewer_v1.py
- ai_code_reviewer_config.json

Then add the stage from `Jenkinsfile.example`.

## MCP later

Edit `ai_code_reviewer_config.json`:

```json
"mcp": {
  "enabled": true,
  "server_url": "YOUR_MCP_SERVER_URL_HERE",
  "token": "YOUR_TOKEN_HERE",
  "tool_name": "review_code"
}
```

Or set environment variables:

```powershell
$env:MCP_SERVER_URL="YOUR_MCP_SERVER_URL_HERE"
$env:MCP_TOKEN="YOUR_TOKEN_HERE"
```
