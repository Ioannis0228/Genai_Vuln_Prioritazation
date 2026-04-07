import requests

def fetch_nvd_cvss(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        res = requests.get(url, timeout=3)
        data = res.json()

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, None

        metrics = vulns[0]["cve"].get("metrics", {})

        if metrics.get("cvssMetricV4"):
            return metrics["cvssMetricV4"][0]["cvssData"]["baseScore"], "4.0"
        if metrics.get("cvssMetricV31"):
            return metrics["cvssMetricV31"][0]["cvssData"]["baseScore"], "3.1"
        if metrics.get("cvssMetricV30"):
            return metrics["cvssMetricV30"][0]["cvssData"]["baseScore"], "3.0"
        if metrics.get("cvssMetricV2"):
            return metrics["cvssMetricV2"][0]["cvssData"]["baseScore"], "2.0"
        

    except Exception:
        print(f"Error fetching CVSS for {cve_id}")
        return None, None