# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import httpx, os
from dotenv import load_dotenv
load_dotenv()
k=os.getenv('OTX_API_KEY')
r=httpx.get('https://otx.alienvault.com/api/v1/indicators/cve/CVE-2021-44228/general', headers={'X-OTX-API-KEY': k}).json()
for i in range(10):
    p0=r['pulse_info']['pulses'][i]
    p_r=httpx.get(f"https://otx.alienvault.com/api/v1/pulses/{p0['id']}/indicators", headers={'X-OTX-API-KEY': k}).json()
    types = set(i.get('type') for i in p_r.get('results',[]))
    print(f"Pulse {i} ({p0['name'][:20]}) types:", types)

