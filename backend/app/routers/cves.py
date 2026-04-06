# -----------------------------------------------------------
# VulnForge – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# -----------------------------------------------------------

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select, func
from typing import Optional
from ..models import CVE, IoC
from ..database import get_session
from ..auth import verify_credentials

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("/", summary="List CVEs with optional filtering and pagination")
def list_cves(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,       # CRITICAL, HIGH, MEDIUM, LOW
    kev_only: bool = False,
    search: Optional[str] = None,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    query = select(CVE)
    if severity:
        query = query.where(CVE.cvss_v3_severity == severity.upper())
    if kev_only:
        query = query.where(CVE.is_kev == True)
    if search:
        query = query.where(CVE.cve_id.contains(search) | CVE.description.contains(search))
    query = query.order_by(CVE.cvss_v3_score.desc()).offset(skip).limit(limit)
    return session.exec(query).all()


@router.get("/stats", summary="Get summary statistics for the dashboard")
def get_stats(
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    total = session.exec(select(func.count(CVE.id))).one()
    critical = session.exec(select(func.count(CVE.id)).where(CVE.cvss_v3_severity == "CRITICAL")).one()
    high = session.exec(select(func.count(CVE.id)).where(CVE.cvss_v3_severity == "HIGH")).one()
    medium = session.exec(select(func.count(CVE.id)).where(CVE.cvss_v3_severity == "MEDIUM")).one()
    low = session.exec(select(func.count(CVE.id)).where(CVE.cvss_v3_severity == "LOW")).one()
    kev = session.exec(select(func.count(CVE.id)).where(CVE.is_kev == True)).one()
    total_iocs = session.exec(select(func.count(IoC.id))).one()

    return {
        "total_cves": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "kev_count": kev,
        "total_iocs": total_iocs,
    }


@router.get("/{cve_id}", summary="Get a specific CVE with its IoCs")
def get_cve(
    cve_id: str,
    _user: str = Depends(verify_credentials),
    session: Session = Depends(get_session),
):
    cve = session.exec(select(CVE).where(CVE.cve_id == cve_id)).first()
    if not cve:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="CVE not found")
    iocs = session.exec(select(IoC).where(IoC.cve_id == cve_id)).all()
    return {**cve.dict(), "iocs": [i.dict() for i in iocs]}

