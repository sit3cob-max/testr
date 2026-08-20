#!/usr/bin/env bash
set -e
python3 automatic.py --workspace . --coverage-file coverage.xml --junit-pattern "reports/TEST-*.xml"
echo "Open pipeline_improver_report.html in your browser"
