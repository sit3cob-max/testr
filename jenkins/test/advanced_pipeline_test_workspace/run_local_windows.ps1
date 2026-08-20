Write-Host "Running Pipeline Automation Improver advanced workspace test"
python automatic.py --workspace . --coverage-file coverage.xml --junit-pattern "reports\TEST-*.xml"
Write-Host "Open report with: start pipeline_improver_report.html"
