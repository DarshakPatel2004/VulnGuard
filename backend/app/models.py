# ═══════════════════════════════════════════════════════════
# VulnTracker – Precision Threat Intelligence Platform
# Made by Darshak Patel
# [dp-watermark-2026]
# ═══════════════════════════════════════════════════════════

from sqlmodel import SQLModel, Field, Column
from sqlalchemy import JSON
from typing import Optional, List
from datetime import datetime


class CVE(SQLModel, table=True):
    """Represents a CVE record fetched from NVD."""
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(index=True, unique=True)
    description: str = Field(default="")
    cvss_v3_score: Optional[float] = Field(default=None)
    cvss_v3_severity: Optional[str] = Field(default=None)
    cvss_v2_score: Optional[float] = Field(default=None)
    published: Optional[datetime] = Field(default=None)
    last_modified: Optional[datetime] = Field(default=None)
    is_kev: bool = Field(default=False)          # flagged by CISA KEV
    kev_date_added: Optional[datetime] = Field(default=None)
    references: Optional[str] = Field(default=None)  # JSON string
    cpes: Optional[str] = Field(default=None)         # JSON string
    created_at: datetime = Field(default_factory=datetime.utcnow)


class IoC(SQLModel, table=True):
    """An Indicator of Compromise linked to a CVE (from OTX)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(index=True)
    ioc_type: str        # ip, domain, file_hash, url
    value: str
    pulse_name: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Asset(SQLModel, table=True):
    """An on-premises asset/device tracked by the user."""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = Field(default=None)
    ip_address: Optional[str] = Field(default=None)
    cpe: Optional[str] = Field(default=None)   # CPE string for matching
    tags: Optional[str] = Field(default=None)  # JSON list string
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FetchLog(SQLModel, table=True):
    """Tracks the last successful fetch timestamp per source."""
    id: Optional[int] = Field(default=None, primary_key=True)
    source: str = Field(index=True, unique=True)   # nvd, cisa_kev, otx
    last_fetched: Optional[datetime] = Field(default=None)
    last_run_status: str = Field(default="never")  # success, error, never
    error_message: Optional[str] = Field(default=None)


class GeneratedRule(SQLModel, table=True):
    """A security rule generated from a CVE/IoC."""
    id: Optional[int] = Field(default=None, primary_key=True)
    cve_id: str = Field(index=True)
    rule_type: str      # snort, sigma, json
    content: str        # the raw rule text
    created_at: datetime = Field(default_factory=datetime.utcnow)

