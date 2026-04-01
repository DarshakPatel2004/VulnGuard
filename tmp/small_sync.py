import sys
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add the project root to sys.path so we can import 'backend'
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

# Load .env variables
from dotenv import load_dotenv
load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

from backend.app.services.nvd_service import fetch_nvd

def main():
    print("Starting small incremental NVD sync to clear error status...")
    
    # Pass a 'since' date of just 1 hour ago
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    
    print(f"Syncing NVD since {since.isoformat()}...")
    nvd_res = fetch_nvd(since=since)
    print(f"NVD Sync Results: {nvd_res}")
    
    print("Incremental sync completed.")

if __name__ == "__main__":
    main()
