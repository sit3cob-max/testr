# Advanced Pipeline Improver Test Workspace

This workspace is designed to test the Pipeline Automation Improver end to end.

It includes:
- Good code
- Intentionally risky code patterns
- Fake JUnit report
- Fake low coverage report
- Jenkinsfile
- Dockerfile
- YAML config
- Java, Python, JavaScript, shell and Groovy files

Important: The risky files are for scanner testing only. Do not use them in production.

## Run from PowerShell

Copy this folder anywhere, then run:

```powershell
python C:\Users\sit3cob\source\repos\automatic_build\automatic.py `
  --workspace . `
  --coverage-file coverage.xml `
  --junit-pattern "reports\TEST-*.xml"
```

If `automatic.py` is inside the same folder, run:

```powershell
python automatic.py --workspace . --coverage-file coverage.xml --junit-pattern "reports\TEST-*.xml"
```

## Expected result

The quality gate should fail or show high risk because this workspace intentionally includes:

- Hardcoded dummy secrets
- eval usage
- shell=True usage
- bare except
- TODO/FIXME comments
- skipped tests in JUnit XML
- low coverage
- large and complex file
- Dockerfile risky pattern
- Jenkinsfile risky pattern

Generated files:

- pipeline_improver_report.json
- pipeline_improver_report.html
- .pipeline_improver_history.json
