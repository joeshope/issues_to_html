import requests
import json
import subprocess
import os
import sys
import re

# --- AUTHENTICATION ---
SNYK_TOKEN = os.getenv("SNYK_TOKEN")
if not SNYK_TOKEN:
    print("Error: SNYK_TOKEN environment variable not set.")
    sys.exit(1)

def get_org_uuid(api_root, org_slug):
    """Resolves an Organization Slug into a UUID via the Snyk API."""
    url = f"{api_root}/orgs?slug={org_slug}&version=2025-11-05"
    headers = {"Authorization": f"token {SNYK_TOKEN}", "Content-Type": "application/vnd.api+json"}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        orgs = data.get('data', [])
        if orgs:
            # The ID is at the root of the object
            return orgs[0].get('id')
    
    print(f"Error: Could not resolve org slug '{org_slug}'.")
    sys.exit(1)

def parse_cli_input():
    """Parses stdin to extract host, org slug, and project UUID."""
    input_text = sys.stdin.read()
    pattern = r"https://(app[\w\.]*)\.snyk\.io/org/([a-zA-Z0-9_-]+)/project/([a-f0-9-]+)"
    match = re.search(pattern, input_text)
    
    if not match:
        print("Error: No valid Snyk URL found in input. Pipe 'snyk monitor' output to this script.")
        sys.exit(1)
        
    app_host = match.group(1)
    org_slug = match.group(2)
    project_id = match.group(3)
    
    api_root = f"https://{app_host.replace('app', 'api')}.snyk.io/rest"
    org_uuid = get_org_uuid(api_root, org_slug)
    
    return api_root, org_uuid, project_id

def fetch_all_issues(api_root, org_uuid, project_id):
    """Fetches non-ignored vulnerabilities and maps them to the detailed legacy format."""
    all_vulnerabilities = []
    headers = {"Authorization": f"token {SNYK_TOKEN}", "Content-Type": "application/vnd.api+json"}
    
    pkg_manager = "npm"
    next_url = f"{api_root}/orgs/{org_uuid}/issues?version=2025-11-05&scan_item.id={project_id}&scan_item.type=project&limit=100"
    
    print(f"Fetching active issues for Project: {project_id}...")

    while next_url:
        url = f"{api_root.split('/rest')[0]}{next_url}" if next_url.startswith('/rest') else next_url
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print(f"API Error: {response.status_code}")
            break

        data = response.json()
        for issue in data.get('data', []):
            attrs = issue.get('attributes', {})
            
            # 1. Skip ignored issues
            if attrs.get('ignored', False):
                continue

            # 2. Extract package details from representations
            coords = attrs.get('coordinates', [{}])[0]
            rep = coords.get('representations', [{}])[0]
            dep = rep.get('dependency', {})
            
            pkg_name = dep.get('package_name', 'unknown')
            pkg_version = dep.get('package_version', 'unknown')

            # 3. Extract remediation (Fixed In) if available
            # Mapping API 'is_upgradeable' to HTML template logic
            fixed_in = []
            if coords.get('is_upgradeable'):
                # In Snyk Legacy, fixedIn is typically an array of versions
                # Note: REST API versioning details may vary; we default to 'See Snyk App' 
                # or a placeholder if the specific target version isn't in this endpoint view.
                fixed_in = ["Upgrade available"] 

            all_vulnerabilities.append({
                "id": attrs.get('key'),
                "title": attrs.get('title'),
                "name": pkg_name,              # Populates 'Vulnerable module'
                "version": pkg_version,        # Populates 'Vulnerable module' version
                "packageName": pkg_name,
                "severity": attrs.get('effective_severity_level'),
                "packageManager": pkg_manager, # Populates per-vuln section
                "fixedIn": fixed_in,           # Populates 'Fixed in' section
                "from": [f"{pkg_name}@{pkg_version}"],
                "isUpgradable": coords.get('is_upgradeable', False),
                "isPatchable": coords.get('is_patchable', False)
            })
        
        next_url = data.get('links', {}).get('next')
    
    return all_vulnerabilities, pkg_manager

def main():
    api_root, org_uuid, project_id = parse_cli_input()
    vulnerabilities, pkg_manager = fetch_all_issues(api_root, org_uuid, project_id)
    
    # Root object required by snyk-to-html
    report_payload = {
        "vulnerabilities": vulnerabilities,
        "ok": len(vulnerabilities) == 0,
        "uniqueCount": len(vulnerabilities),
        "path": project_id,
        "packageManager": pkg_manager
    }

    temp_file = "temp_data.json"
    with open(temp_file, "w") as f:
        json.dump(report_payload, f)

    print(f"Generating detailed HTML for {len(vulnerabilities)} vulnerabilities...")
    subprocess.run(["snyk-to-html", "-i", temp_file, "-o", "snyk_report.html"])
    
    if os.path.exists(temp_file):
        os.remove(temp_file)
    print("Success: snyk_report.html created.")

if __name__ == "__main__":
    main()
