import json
from cyclonedx.model.bom import Bom

def parse_sbom(input_file: str):
    with open(input_file,'r', encoding='utf-8') as f:
        json_data = json.load(f)

    sbom = Bom.from_json(json_data)

    return sbom


def normalize_component(c):
    return {
        "type": str(c.type),
        "bom_ref": str(c.bom_ref) if c.bom_ref else None,
        "name": c.name,
        "version": c.version or None,
        "description": c.description,
        "purl": str(c.purl) if c.purl else None,
        "cpe": str(c.cpe) if c.cpe else None,
    }