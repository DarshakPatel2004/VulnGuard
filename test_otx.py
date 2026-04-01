# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

import httpx

url = "https://otx.alienvault.com/api/v1/indicators/cve/CVE-2021-44228/general"
resp = httpx.get(url)
data = resp.json()

pulses = data.get("pulse_info", {}).get("pulses", [])
if not pulses:
    pulses = data.get("pulses", [])

print("Found pulses:", len(pulses))
if pulses:
    print("Pulse 0 keys:", pulses[0].keys())
    print("Does Pulse 0 have indicators?", "indicators" in pulses[0])
    print("Pulse 0 indicators:", pulses[0].get("indicators", [])[:2])

