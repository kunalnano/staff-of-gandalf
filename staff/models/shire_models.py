"""
Shire Models
~~~~~~~~~~~~

Data models for network inventory, baselining, and device tracking.

"Keep it secret, keep it safe."
"""

from datetime import datetime
from typing import Optional, Literal

from pydantic import BaseModel, Field


class ShireDevice(BaseModel):
    """A device discovered on the network — a resident of the Shire."""

    ip_address: str = Field(..., description="IP address")
    mac_address: Optional[str] = Field(None, description="MAC address")
    vendor: Optional[str] = Field(None, description="MAC vendor/manufacturer")
    hostname: Optional[str] = Field(None, description="Resolved hostname")
    open_ports: list[int] = Field(default_factory=list, description="Open ports found")
    os_guess: Optional[str] = Field(None, description="OS fingerprint guess")
    first_seen: datetime = Field(default_factory=datetime.now, description="First seen timestamp")
    last_seen: datetime = Field(default_factory=datetime.now, description="Last seen timestamp")
    label: Optional[str] = Field(None, description="User-assigned friendly name")
    status: Literal["known", "new", "missing", "suspicious"] = Field(
        "new", description="Device classification"
    )

    @property
    def display_name(self) -> str:
        """Best available name for this device."""
        if self.label:
            return self.label
        if self.hostname and self.hostname != self.ip_address:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} device"
        return self.ip_address

    @property
    def identity_key(self) -> str:
        """Unique key for matching — MAC preferred, IP fallback."""
        return self.mac_address.upper() if self.mac_address else self.ip_address


class ShireBaseline(BaseModel):
    """A saved snapshot of known network residents."""

    name: str = Field(default="default", description="Baseline profile name")
    network: str = Field(..., description="Network CIDR that was scanned")
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    devices: list[ShireDevice] = Field(default_factory=list)

    @property
    def device_count(self) -> int:
        return len(self.devices)

    def find_by_mac(self, mac: str) -> Optional[ShireDevice]:
        """Find a device by MAC address."""
        mac_upper = mac.upper()
        for d in self.devices:
            if d.mac_address and d.mac_address.upper() == mac_upper:
                return d
        return None

    def find_by_ip(self, ip: str) -> Optional[ShireDevice]:
        """Find a device by IP address."""
        for d in self.devices:
            if d.ip_address == ip:
                return d
        return None

    def to_json_dict(self) -> dict:
        """Serialize for JSON storage."""
        data = self.model_dump()
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        for d in data["devices"]:
            d["first_seen"] = d["first_seen"].isoformat() if isinstance(d["first_seen"], datetime) else d["first_seen"]
            d["last_seen"] = d["last_seen"].isoformat() if isinstance(d["last_seen"], datetime) else d["last_seen"]
        return data

    @classmethod
    def from_json_dict(cls, data: dict) -> "ShireBaseline":
        """Deserialize from JSON."""
        if isinstance(data.get("created_at"), str):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if isinstance(data.get("updated_at"), str):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        for d in data.get("devices", []):
            if isinstance(d.get("first_seen"), str):
                d["first_seen"] = datetime.fromisoformat(d["first_seen"])
            if isinstance(d.get("last_seen"), str):
                d["last_seen"] = datetime.fromisoformat(d["last_seen"])
        return cls(**data)


class ShireDiff(BaseModel):
    """Result of comparing a scan against a baseline."""

    known_present: list[ShireDevice] = Field(default_factory=list, description="Known devices found")
    strangers: list[ShireDevice] = Field(default_factory=list, description="Unknown devices found")
    missing: list[ShireDevice] = Field(default_factory=list, description="Known devices not found")
    changed: list[dict] = Field(default_factory=list, description="Devices with changed attributes")

    @property
    def is_clean(self) -> bool:
        return len(self.strangers) == 0

    @property
    def threat_level(self) -> str:
        if len(self.strangers) == 0:
            return "peaceful"
        elif len(self.strangers) <= 2:
            return "watchful"
        else:
            return "alarmed"
