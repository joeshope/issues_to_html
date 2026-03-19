# This script leverages the output from the Snyk SBOM Monitor command to provide a Snyk HTML Report

There are limitations to this script since it leverages more limited data than the output from the Snyk CLI. An example of the output is included under examples/snyk_report.html.

# Prerequisites
- a Snyk token saved in the $SNYK_TOKEN env var

# Installation
pip install -r requirements.txt

# Usage
snyk sbom monitor --experimental --file=my_sbom.json --remote-repo-url=https://github.com/my/repo | python3 snyk_report.py
