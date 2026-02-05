"""
Shire Scanner
~~~~~~~~~~~~~

Network inventory, device fingerprinting, and baseline management.
Wraps nmap for discovery and adds MAC vendor identification.

"The Shire must be protected at all costs."
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import nmap

from staff.config import TimingMode, console, settings
from staff.models.shire_models import ShireBaseline, ShireDevice, ShireDiff


# ---------------------------------------------------------------------------
# MAC Vendor Lookup (with graceful fallback)
# ---------------------------------------------------------------------------

_vendor_lookup = None


def _get_vendor_lookup():
    """Lazy-load the MAC vendor lookup. Falls back to None if unavailable."""
    global _vendor_lookup
    if _vendor_lookup is None:
        try:
            from mac_vendor_lookup import MacLookup
            _vendor_lookup = MacLookup()
            # Try to update the vendor database on first use
            try:
                _vendor_lookup.update_vendors()
            except Exception:
                pass  # Use bundled DB if update fails
        except ImportError:
            _vendor_lookup = False  # Sentinel: tried but unavailable
    return _vendor_lookup if _vendor_lookup is not False else None


def lookup_vendor(mac: str) -> Optional[str]:
    """Look up the manufacturer for a MAC address."""
    if not mac:
        return None
    ml = _get_vendor_lookup()
    if ml is None:
        return None
    try:
        return ml.lookup(mac)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Baseline Storage
# ---------------------------------------------------------------------------

def _baselines_dir() -> Path:
    """Get the baselines storage directory."""
    d = Path(settings.reports_dir) / "shire_baselines"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _baseline_path(name: str = "default") -> Path:
    """Get path for a named baseline file."""
    safe = name.replace("/", "_").replace("\\", "_").replace(" ", "_")
    return _baselines_dir() / f"baseline_{safe}.json"


def save_baseline(baseline: ShireBaseline) -> Path:
    """Save a baseline to disk."""
    path = _baseline_path(baseline.name)
    with open(path, "w") as f:
        json.dump(baseline.to_json_dict(), f, indent=2)
    return path


def load_baseline(name: str = "default") -> Optional[ShireBaseline]:
    """Load a baseline from disk."""
    path = _baseline_path(name)
    if not path.exists():
        return None
    with open(path) as f:
        data = json.load(f)
    return ShireBaseline.from_json_dict(data)


def list_baselines() -> list[dict]:
    """List all saved baselines with metadata."""
    results = []
    bdir = _baselines_dir()
    for f in sorted(bdir.glob("baseline_*.json")):
        try:
            with open(f) as fh:
                data = json.load(fh)
            results.append({
                "name": data.get("name", f.stem),
                "network": data.get("network", "unknown"),
                "device_count": len(data.get("devices", [])),
                "updated_at": data.get("updated_at", "unknown"),
                "path": str(f),
            })
        except Exception:
            continue
    return results


# ---------------------------------------------------------------------------
# Network Scanning
# ---------------------------------------------------------------------------

def scan_network(target: str, timing: TimingMode = TimingMode.DEFAULT, quick_ports: bool = True) -> list[ShireDevice]:
    """
    Scan a network and return enriched device list.

    Runs nmap host discovery + optional quick port scan, then enriches
    each result with MAC vendor identification.

    Args:
        target: CIDR range like 192.168.1.0/24
        timing: Scan timing mode
        quick_ports: Also do a fast port scan (top 100 ports)

    Returns:
        List of ShireDevice objects
    """
    nm = nmap.PortScanner()
    timing_flag = settings.timing_templates.get(timing, "-T3")

    # Phase 1: Host discovery with MAC addresses
    # -sn for ping sweep, --send-ip to get MAC via ARP on local net
    discover_args = f"-sn {timing_flag}"
    console.print(f"[info]Phase 1 — Host discovery: nmap {discover_args} {target}[/info]")

    try:
        nm.scan(hosts=target, arguments=discover_args)
    except nmap.PortScannerError as e:
        if "requires root privileges" in str(e).lower():
            raise PermissionError(
                "Root privileges needed to see MAC addresses. Run with sudo."
            ) from e
        raise RuntimeError(f"Scan failed: {e}") from e

    devices: list[ShireDevice] = []
    now = datetime.now()

    for host in nm.all_hosts():
        host_data = nm[host]

        # Extract hostname
        hostname = None
        if "hostnames" in host_data and host_data["hostnames"]:
            for hn in host_data["hostnames"]:
                if hn.get("name"):
                    hostname = hn["name"]
                    break

        # Extract MAC
        mac = None
        if "addresses" in host_data and "mac" in host_data["addresses"]:
            mac = host_data["addresses"]["mac"]

        # Vendor lookup
        vendor = lookup_vendor(mac)

        # Also check if nmap gave us a vendor
        if not vendor and "vendor" in host_data:
            vendor_dict = host_data.get("vendor", {})
            if mac and mac in vendor_dict:
                vendor = vendor_dict[mac]

        devices.append(ShireDevice(
            ip_address=host,
            mac_address=mac,
            vendor=vendor,
            hostname=hostname,
            first_seen=now,
            last_seen=now,
        ))

    # Phase 2: Quick port scan if requested
    if quick_ports and devices:
        console.print(f"[info]Phase 2 — Quick port scan on {len(devices)} host(s)...[/info]")
        alive_ips = " ".join(d.ip_address for d in devices)
        port_args = f"-F --open {timing_flag}"

        try:
            nm.scan(hosts=alive_ips, arguments=port_args)
            for device in devices:
                if device.ip_address in nm.all_hosts():
                    host_data = nm[device.ip_address]
                    ports = []
                    for proto in host_data.all_protocols():
                        for port in host_data[proto]:
                            if host_data[proto][port].get("state") == "open":
                                ports.append(port)
                    device.open_ports = sorted(ports)
        except Exception as e:
            console.print(f"[warning]Port scan phase failed (non-fatal): {e}[/warning]")

    return devices


# ---------------------------------------------------------------------------
# Diff Engine
# ---------------------------------------------------------------------------

def compare_to_baseline(current_devices: list[ShireDevice], baseline: ShireBaseline) -> ShireDiff:
    """
    Compare a current scan against a saved baseline.

    Matching priority:
    1. MAC address (most reliable — persists across DHCP reassignment)
    2. IP address fallback (for devices where MAC wasn't captured)
    """
    diff = ShireDiff()

    # Build lookup from baseline
    baseline_by_mac = {}
    baseline_by_ip = {}
    matched_baseline_keys = set()

    for bd in baseline.devices:
        if bd.mac_address:
            baseline_by_mac[bd.mac_address.upper()] = bd
        baseline_by_ip[bd.ip_address] = bd

    for device in current_devices:
        matched = None

        # Try MAC match first
        if device.mac_address:
            matched = baseline_by_mac.get(device.mac_address.upper())

        # Fallback to IP match
        if not matched:
            matched = baseline_by_ip.get(device.ip_address)

        if matched:
            device.status = "known"
            device.label = matched.label  # Carry forward user labels
            device.first_seen = matched.first_seen
            matched_baseline_keys.add(matched.identity_key)
            diff.known_present.append(device)

            # Check for changes
            changes = []
            if device.ip_address != matched.ip_address:
                changes.append({"field": "ip", "old": matched.ip_address, "new": device.ip_address})
            if device.hostname != matched.hostname and matched.hostname:
                changes.append({"field": "hostname", "old": matched.hostname, "new": device.hostname})
            if set(device.open_ports) != set(matched.open_ports):
                changes.append({
                    "field": "ports",
                    "old": matched.open_ports,
                    "new": device.open_ports,
                })
            if changes:
                diff.changed.append({"device": device.display_name, "mac": device.mac_address, "changes": changes})
        else:
            device.status = "new"
            diff.strangers.append(device)

    # Find missing devices
    for bd in baseline.devices:
        if bd.identity_key not in matched_baseline_keys:
            bd.status = "missing"
            diff.missing.append(bd)

    return diff


# ---------------------------------------------------------------------------
# Label Management
# ---------------------------------------------------------------------------

def label_device(baseline_name: str, identifier: str, label: str) -> bool:
    """
    Assign a friendly name to a device in a baseline.

    Args:
        baseline_name: Name of the baseline
        identifier: MAC or IP to match
        label: Friendly name to assign

    Returns:
        True if device was found and labeled
    """
    bl = load_baseline(baseline_name)
    if not bl:
        return False

    identifier_upper = identifier.upper()
    for d in bl.devices:
        if (d.mac_address and d.mac_address.upper() == identifier_upper) or d.ip_address == identifier:
            d.label = label
            bl.updated_at = datetime.now()
            save_baseline(bl)
            return True
    return False
