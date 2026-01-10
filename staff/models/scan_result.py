"""
Pydantic Models for Scan Results
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Data models for structured scan data across all scanner modules.

"All we have to decide is what to do with the data that is given us."
"""

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class HostResult(BaseModel):
    """Result from host discovery scan."""

    ip_address: str = Field(..., description="IP address of the discovered host")
    hostname: Optional[str] = Field(None, description="Hostname if resolvable")
    status: Literal["up", "down"] = Field(..., description="Host status")
    mac_address: Optional[str] = Field(None, description="MAC address if available")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Basic IP address format validation."""
        parts = v.split(".")
        if len(parts) == 4:
            try:
                if all(0 <= int(part) <= 255 for part in parts):
                    return v
            except ValueError:
                pass
        # Also accept IPv6
        if ":" in v:
            return v
        raise ValueError(f"Invalid IP address format: {v}")


class ServiceInfo(BaseModel):
    """Service information detected on a port."""

    name: str = Field(..., description="Service name")
    product: Optional[str] = Field(None, description="Product name")
    version: Optional[str] = Field(None, description="Service version")
    extra_info: Optional[str] = Field(None, description="Additional information")


class PortResult(BaseModel):
    """Result from port scan."""

    port: int = Field(..., ge=1, le=65535, description="Port number")
    protocol: Literal["tcp", "udp"] = Field(..., description="Protocol")
    state: Literal["open", "closed", "filtered"] = Field(..., description="Port state")
    service: Optional[str] = Field(None, description="Service name")
    version: Optional[str] = Field(None, description="Service version")
    scripts: Optional[dict] = Field(None, description="NSE script output")


class Finding(BaseModel):
    """Security finding with severity classification."""

    severity: Literal["critical", "warning", "info"] = Field(
        ..., description="Severity level"
    )
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    port: Optional[int] = Field(None, description="Related port number")
    host: str = Field(..., description="Affected host")
    recommendation: str = Field(..., description="Recommended action")

    @property
    def emoji(self) -> str:
        """Get severity emoji for reports."""
        emojis = {"critical": "🔴", "warning": "🟡", "info": "🟢"}
        return emojis.get(self.severity, "⚪")


class ScryResult(BaseModel):
    """OSINT results from WHOIS and DNS lookups."""

    domain: str = Field(..., description="Target domain")
    whois_data: dict = Field(default_factory=dict, description="WHOIS lookup data")
    dns_records: dict = Field(
        default_factory=dict,
        description="DNS records by type (A, AAAA, MX, TXT, NS, CNAME, SOA)",
    )
    registrar: Optional[str] = Field(None, description="Domain registrar")
    creation_date: Optional[datetime] = Field(None, description="Domain creation date")
    name_servers: list[str] = Field(
        default_factory=list, description="Name server list"
    )


class ScanSession(BaseModel):
    """Complete scan session with all results."""

    target: str = Field(..., description="Scan target (IP, hostname, or CIDR)")
    timestamp: datetime = Field(
        default_factory=datetime.now, description="Scan start time"
    )
    timing_mode: Literal["default", "stealth", "aggressive"] = Field(
        "default", description="Scan timing mode"
    )
    illuminate_results: Optional[list[HostResult]] = Field(
        None, description="Host discovery results"
    )
    shadowfax_results: Optional[dict] = Field(None, description="Fast port scan results")
    delve_results: Optional[dict] = Field(None, description="Deep scan results")
    scry_results: Optional[ScryResult] = Field(None, description="OSINT results")
    findings: list[Finding] = Field(
        default_factory=list, description="Security findings"
    )

    def to_json_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        data = self.model_dump()
        # Convert datetime to ISO string
        data["timestamp"] = self.timestamp.isoformat()
        if self.scry_results and self.scry_results.creation_date:
            data["scry_results"]["creation_date"] = (
                self.scry_results.creation_date.isoformat()
            )
        return data

    @classmethod
    def from_json_dict(cls, data: dict) -> "ScanSession":
        """Create from JSON dict, handling datetime conversion."""
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        if data.get("scry_results") and isinstance(
            data["scry_results"].get("creation_date"), str
        ):
            data["scry_results"]["creation_date"] = datetime.fromisoformat(
                data["scry_results"]["creation_date"]
            )
        return cls(**data)
