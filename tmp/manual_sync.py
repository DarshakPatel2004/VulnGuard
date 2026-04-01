import sys
import os
from pathlib import Path

# Add the project root to sys.path so we can import 'backend'
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

# Load .env variables
from dotenv import load_dotenv
load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

from backend.app.services.nvd_service import fetch_nvd
from backend.app.services.cisa_kev_service import fetch_cisa_kev
from backend.app.services.otx_service import fetch_otx_for_recent_cves
from backend.app.rule_generator import generate_all_rules

def main():
    print("Starting manual sync to clear errors...")
    
    # Trigger NVD fetch (incremental)
    # We'll use since=None to force a full fetch or at least a fresh one
    # Note: A full fetch might take a long time, but we just want to clear the 404
    print("Syncing NVD...")
    nvd_res = fetch_nvd(since=None)
    print(f"NVD Sync Results: {nvd_res}")
    
    # Trigger CISA KEV
    print("Syncing CISA KEV...")
    kev_res = fetch_cisa_kev()
    print(f"CISA KEV Sync Results: {kev_res}")
    
    # Trigger OTX
    print("Syncing OTX...")
    otx_res = fetch_otx_for_recent_cves(limit=50)
    print(f"OTX Sync Results: {otx_res}")
    
    # Regenerate rules
    print("Regenerating Rules...")
    rule_res = generate_all_rules()
    print(f"Rule Generation Results: {rule_res}")
    
    print("Manual sync completed.")

if __name__ == "__main__":
    main()
