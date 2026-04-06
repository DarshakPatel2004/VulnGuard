# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, FileResponse
from pathlib import Path
import os
from ..auth import verify_credentials
from ..rule_generator import generate_snort_rules, generate_sigma_rules, generate_json_alerts, OUTPUT_DIR

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/snort", summary="Get Snort/Suricata rules (text/plain)")
def get_snort_rules(_user: str = Depends(verify_credentials)):
    content = generate_snort_rules()
    return PlainTextResponse(content, media_type="text/plain")


@router.get("/snort/download", summary="Download Snort rules file")
def download_snort_rules(_user: str = Depends(verify_credentials)):
    path = OUTPUT_DIR / "snort.rules"
    if not path.exists():
        generate_snort_rules()
    return FileResponse(path, filename="snort.rules", media_type="text/plain")


@router.get("/sigma", summary="Get Sigma rules (YAML)")
def get_sigma_rules(_user: str = Depends(verify_credentials)):
    content = generate_sigma_rules()
    return PlainTextResponse(content, media_type="text/yaml")


@router.get("/sigma/download", summary="Download Sigma rules file")
def download_sigma_rules(_user: str = Depends(verify_credentials)):
    path = OUTPUT_DIR / "sigma.yml"
    if not path.exists():
        generate_sigma_rules()
    return FileResponse(path, filename="sigma.yml", media_type="text/yaml")


@router.get("/json", summary="Get JSON alert feed")
def get_json_alerts(_user: str = Depends(verify_credentials)):
    content = generate_json_alerts()
    import json
    return json.loads(content)


@router.get("/json/download", summary="Download JSON alerts file")
def download_json_alerts(_user: str = Depends(verify_credentials)):
    path = OUTPUT_DIR / "alerts.json"
    if not path.exists():
        generate_json_alerts()
    return FileResponse(path, filename="alerts.json", media_type="application/json")

