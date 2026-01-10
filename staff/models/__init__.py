"""
Data Models
~~~~~~~~~~~

Pydantic models for structured scan data.

Models:
    - HostResult: Individual host discovery result
    - PortResult: Port scan result with service info
    - ServiceInfo: Service name, product, and version
    - Finding: Security finding with severity
    - ScryResult: OSINT results (WHOIS, DNS)
    - ScanSession: Complete scan session data

"All we have to decide is what to do with the data that is given us."
"""

from staff.models.scan_result import (
    HostResult,
    PortResult,
    ServiceInfo,
    Finding,
    ScryResult,
    ScanSession,
)

__all__ = [
    "HostResult",
    "PortResult",
    "ServiceInfo",
    "Finding",
    "ScryResult",
    "ScanSession",
]
