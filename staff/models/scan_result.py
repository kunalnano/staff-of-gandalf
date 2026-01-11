"""
Scan Result Models
~~~~~~~~~~~~~~~~~~

Pydantic models for hosts, ports, services, and findings.

"Even the smallest person can change the course of the future."
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class HostResult(BaseModel):
    """Result of host discovery."""

    ip_address: str
    hostname: Optional[str] = None
    status: Literal["up", "down"] = "up"
    mac_address: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP address validation."""
        parts = v.split(".")
        if len(parts) == 4:
            try:
                for part in parts:
                    num = int(part)
                    if num < 0 or num > 255:
                        raise ValueError("IP octet out of range")
                return v
            except ValueError:
                pass
        # Allow IPv6 and hostnames too
        if ":" in v or v.replace(".", "").replace("-", "").isalnum():
            return v
        raise ValueError(f"Invalid IP address format: {v}")


class PortResult(BaseModel):
    """Result of port scan."""

    port: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    state: Literal["open", "closed", "filtered"] = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    scripts: Optional[dict] = None


class ServiceInfo(BaseModel):
    """Detailed service information."""

    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None


class Finding(BaseModel):
    """Security finding from analysis."""

    severity: Literal["critical", "warning", "info"]
    title: str
    description: str
    port: Optional[int] = None
    host: str
    recommendation: str


class ScryResult(BaseModel):
    """OSINT lookup results."""

    domain: str
    whois_data: dict = Field(default_factory=dict)
    dns_records: dict = Field(default_factory=dict)
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    name_servers: list[str] = Field(default_factory=list)


class ScanSession(BaseModel):
    """Complete scan session with all phases."""

    target: str
    timestamp: datetime = Field(default_factory=datetime.now)
    timing_mode: str = "default"
    illuminate_results: Optional[list[HostResult]] = None
    shadowfax_results: Optional[dict] = None
    delve_results: Optional[dict] = None
    scry_results: Optional[ScryResult] = None
    findings: list[Finding] = Field(default_factory=list)

    def to_json_dict(self) -> dict:
        """Convert to JSON-serializable dictionary."""
        data = {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "timing_mode": self.timing_mode,
            "illuminate_results": None,
            "shadowfax_results": self.shadowfax_results,
            "delve_results": self.delve_results,
            "scry_results": None,
            "findings": [f.model_dump() for f in self.findings],
        }

        if self.illuminate_results:
            data["illuminate_results"] = [h.model_dump() for h in self.illuminate_results]

        if self.scry_results:
            scry_dict = self.scry_results.model_dump()
            if self.scry_results.creation_date:
                scry_dict["creation_date"] = self.scry_results.creation_date.isoformat()
            data["scry_results"] = scry_dict

        return data

    @classmethod
    def from_json_dict(cls, data: dict) -> "ScanSession":
        """Create ScanSession from JSON dictionary."""
        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)

        # Parse illuminate results
        illuminate_results = None
        if data.get("illuminate_results"):
            illuminate_results = [HostResult(**h) for h in data["illuminate_results"]]

        # Parse scry results
        scry_results = None
        if data.get("scry_results"):
            scry_data = data["scry_results"].copy()
            if scry_data.get("creation_date"):
                if isinstance(scry_data["creation_date"], str):
                    scry_data["creation_date"] = datetime.fromisoformat(
                        scry_data["creation_date"]
                    )
            scry_results = ScryResult(**scry_data)

        # Parse findings
        findings = [Finding(**f) for f in data.get("findings", [])]

        return cls(
            target=data["target"],
            timestamp=timestamp or datetime.now(),
            timing_mode=data.get("timing_mode", "default"),
            illuminate_results=illuminate_results,
            shadowfax_results=data.get("shadowfax_results"),
            delve_results=data.get("delve_results"),
            scry_results=scry_results,
            findings=findings,
        )
