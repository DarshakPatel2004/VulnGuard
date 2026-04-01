import httpx
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

def test_nvd_api():
    # Use a date from a few days ago to ensure results
    since = datetime.now(timezone.utc) - timedelta(days=1)
    
    # New format: YYYY-MM-DDTHH:mm:ss.000
    last_mod_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    last_mod_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    
    params = {
        "resultsPerPage": 1,
        "startIndex": 0,
        "lastModStartDate": last_mod_start,
        "lastModEndDate": last_mod_end
    }
    
    headers = {"Accept": "application/json"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        print("Using API Key")
    else:
        print("No API Key found, rate limiting applies")

    print(f"Requesting URL: {NVD_BASE_URL}")
    print(f"Params: {params}")
    
    try:
        resp = httpx.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)
        print(f"Status Code: {resp.status_code}")
        if resp.status_code == 200:
            print("Success! Received 200 OK from NVD API.")
            data = resp.json()
            print(f"Total Results Found: {data.get('totalResults')}")
        else:
            print(f"Error: {resp.text}")
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    test_nvd_api()
