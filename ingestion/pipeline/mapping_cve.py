import json
import subprocess

def mapping_cve(SBOM_PATH, OUTPUT_PATH):

    result = subprocess.run(
        ["trivy", "sbom", SBOM_PATH, "--format", "json"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("ERROR:", result.stderr)
        raise Exception("Trivy failed")

    if not result.stdout.strip(): 
        raise Exception("Empty output from Trivy scan")
    data = json.loads(result.stdout)


    with open(OUTPUT_PATH, 'w') as f:
        json.dump(data, f, ensure_ascii=False,sort_keys=True, indent=4)

    component_cve = []
        
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            if not v.get("VulnerabilityID", "").startswith("CVE-"):
                continue

            cvss_score, cvss_version = extract_cvss(v.get("CVSS", {}))

            component_cve.append({
                "purl": v["PkgIdentifier"]["PURL"],
                "cve_id": v["VulnerabilityID"],
                "description": v["Description"],
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "published_date": v.get("PublishedDate")
            })    

    return component_cve
    

def extract_cvss(cvss_dict):
    if not cvss_dict:
        return None, None

    nvd = cvss_dict.get("nvd")
    if not nvd:
        return None, None

    if "V4Score" in nvd:
        return nvd["V4Score"], "4.0"

    if "V3Score" in nvd:
        return nvd["V3Score"], "3.x"

    if "V2Score" in nvd:
        return nvd["V2Score"], "2.0"

    return None, None