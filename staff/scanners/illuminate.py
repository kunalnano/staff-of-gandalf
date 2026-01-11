"""
Illuminate Scanner
~~~~~~~~~~~~~~~~~~

Host discovery via nmap -sn ping sweep.

"I am a servant of the Secret Fire, wielder of the flame of Anor."
"""

from typing import Optional

import nmap

from staff.config import TimingMode, console, settings
from staff.models.scan_result import HostResult


def discover_hosts(
    target: str,
    timing: TimingMode = TimingMode.DEFAULT,
) -> list[HostResult]:
    """
    Perform host discovery using nmap ping sweep.

    Args:
        target: IP address, hostname, or CIDR range to scan
        timing: Scan timing mode (default, stealth, aggressive)

    Returns:
        List of discovered hosts

    Raises:
        PermissionError: If root privileges are required but not available
        RuntimeError: If nmap is not installed or scan fails
    """
    nm = nmap.PortScanner()
    timing_flag = settings.timing_templates.get(timing, "-T3")

    # Host discovery only (no port scan)
    arguments = f"-sn {timing_flag}"

    console.print(f"[info]Running: nmap {arguments} {target}[/info]")

    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        if "requires root privileges" in str(e).lower():
            raise PermissionError(
                "Host discovery may require root privileges. Try with sudo."
            ) from e
        if "nmap program was not found" in str(e).lower():
            raise RuntimeError(
                "nmap is not installed. Please install nmap and try again."
            ) from e
        raise RuntimeError(f"Scan failed: {e}") from e

    results: list[HostResult] = []

    for host in nm.all_hosts():
        host_data = nm[host]
        hostname: Optional[str] = None

        # Extract hostname if available
        if "hostnames" in host_data and host_data["hostnames"]:
            for hn in host_data["hostnames"]:
                if hn.get("name"):
                    hostname = hn["name"]
                    break

        # Get MAC address if available
        mac_address: Optional[str] = None
        if "addresses" in host_data:
            mac_address = host_data["addresses"].get("mac")

        # Determine status
        status = "up" if host_data.get("status", {}).get("state") == "up" else "down"

        results.append(
            HostResult(
                ip_address=host,
                hostname=hostname,
                status=status,
                mac_address=mac_address,
            )
        )

    return results
