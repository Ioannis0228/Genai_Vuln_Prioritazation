from database import create_tables
from ingestion import run_pipeline

SBOM_PATH = 'data/juice_bom.json'
OUTPUT_PATH = 'data/scan_results.json'

if __name__ == "__main__":
    create_tables()

    run_pipeline(SBOM_PATH, OUTPUT_PATH)
