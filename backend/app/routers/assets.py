# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from typing import Optional
from ..models import CVE, IoC, Asset
from ..database import get_session
from ..auth import verify_credentials

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("/", summary="List all tracked assets")
def list_assets(
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    assets = session.exec(select(Asset)).all()
    return assets


@router.post("/", summary="Add a new asset to track")
def create_asset(
    asset: Asset,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    session.add(asset)
    session.commit()
    session.refresh(asset)
    return asset


@router.get("/{asset_id}", summary="Get a specific asset")
def get_asset(
    asset_id: int,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.delete("/{asset_id}", summary="Delete an asset")
def delete_asset(
    asset_id: int,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    session.delete(asset)
    session.commit()
    return {"deleted": True, "id": asset_id}


@router.get("/{asset_id}/cves", summary="Get CVEs matching an asset's CPE")
def get_cves_for_asset(
    asset_id: int,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    asset = session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.cpe:
        return {"asset": asset.name, "cves": []}

    # Parse the asset CPE to extract vendor and product
    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
    asset_cpe_parts = asset.cpe.split(":")
    if len(asset_cpe_parts) < 5:
        return {"asset": asset.name, "cpe": asset.cpe, "cves": [], "error": "Invalid CPE format"}

    asset_vendor = asset_cpe_parts[3].lower()  # apache
    asset_product = asset_cpe_parts[4].lower()  # log4j
    asset_version = asset_cpe_parts[5] if len(asset_cpe_parts) > 5 else "*"

    # Search for CVEs where CPE JSON array contains matching vendor:product
    # We search for the pattern ":vendor:product:" in the CPEs JSON
    search_pattern = f':{asset_vendor}:{asset_product}:'

    all_cves = session.exec(select(CVE).where(CVE.cpes.contains(search_pattern))).all()

    # Filter to only CVEs where the asset version matches the vulnerable range
    matching_cves = []
    for cve in all_cves:
        if cve.cpes:
            try:
                import json
                cpes = json.loads(cve.cpes) if cve.cpes.startswith('[') else []
                for cpe in cpes:
                    if _cpe_matches(cpe, asset.cpe):
                        # Convert CVE model to dict for JSON serialization
                        matching_cves.append({
                            "cve_id": cve.cve_id,
                            "description": cve.description,
                            "cvss_v3_score": cve.cvss_v3_score,
                            "cvss_v3_severity": cve.cvss_v3_severity,
                            "cvss_v2_score": cve.cvss_v2_score,
                            "published": cve.published.isoformat() if cve.published else None,
                            "is_kev": cve.is_kev,
                            "references": cve.references,
                        })
                        break
            except json.JSONDecodeError:
                continue

    return {"asset": asset.name, "cpe": asset.cpe, "vendor": asset_vendor, "product": asset_product, "cves": matching_cves}


def _cpe_matches(cve_cpe: str, asset_cpe: str) -> bool:
    """Check if an asset CPE matches a CVE CPE pattern (supports wildcards)."""
    cve_parts = cve_cpe.split(":")
    asset_parts = asset_cpe.split(":")

    if len(cve_parts) < 6 or len(asset_parts) < 6:
        return False

    # Compare each component (part, vendor, product, version, update, edition)
    # CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:...
    for i in range(2, 8):  # Check components 2-7 (part through edition)
        cve_val = cve_parts[i].lower() if i < len(cve_parts) else "*"
        asset_val = asset_parts[i].lower() if i < len(asset_parts) else "*"

        # Wildcards match anything
        if cve_val in ("*", "-", ""):
            continue

        if cve_val != asset_val:
            return False

    return True

