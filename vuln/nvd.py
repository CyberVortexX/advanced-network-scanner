import requests

def fetch_cves(service_name, version):
    if not service_name or not version or version == "Unknown":
        return []

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": f"{service_name} {version}", "resultsPerPage": 5}

    try:
        response = requests.get(base_url, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            cve_list = []
            for v in data.get('vulnerabilities', []):
                cve_id = v['cve']['id']
                metrics = v['cve'].get('metrics', {})
                # Try to get CVSS v3.1 or v3.0 scores
                cvss_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                score = cvss_data[0]['cvssData']['baseScore'] if cvss_data else 0.0
                cve_list.append({"id": cve_id, "score": score})
            return cve_list
        return []
    except Exception:
        return []
