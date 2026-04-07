from database import save_components, save_CVEs, save_KEV_snapshot, save_EPSS_snapshot, get_CVEs_id

from .pipeline.sbom import normalize_component, parse_sbom
from .pipeline.mapping_cve import mapping_cve
from .pipeline.cve import fetch_nvd_cvss
from .pipeline.kev import fetch_KEV
from .pipeline.epss import fetch_EPSS

def run_pipeline(SBOM_PATH, OUTPUT_PATH):

    sbom = parse_sbom(SBOM_PATH)
    normalized_components = [normalize_component(c) for c in sbom.components]
    save_components(normalized_components, dependencies=sbom.dependencies)

    print("Starting CVE mapping...", flush=True)
    component_cve = mapping_cve(SBOM_PATH, OUTPUT_PATH)

    save_CVEs(component_cve)

    # Maybe we fetch data if the last update is > 24h, but for now we just fetch and save
    save_KEV_snapshot(fetch_KEV())

    print("Fetching EPSS data...", flush=True)
    CVEs_id = get_CVEs_id()

    save_EPSS_snapshot(fetch_EPSS(CVEs_id))

    print("Pipeline execution completed successfully.", flush=True)

