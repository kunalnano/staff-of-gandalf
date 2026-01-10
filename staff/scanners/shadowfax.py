"""
Shadowfax Scanner
~~~~~~~~~~~~~~~~~

Fast port scan using nmap -F (top 100 ports).

"Shadowfax is the lord of all horses, and has been my friend through many dangers."
"""

from typing import Optional

import nmap

from staff.config import TimingMode, console, settings
from staff.models.scan_result import PortResult


def fast_scan(
    target: str, timing: TimingMode = TimingMode.DEFAULT
) -> dict[str, list[dict]]:
    """
    Perform fast port scan on target using nmap -F.

    Args:
        target: IP address, hostname, or CIDR range to scan
        timing: Scan timing mode (default, stealth, aggressive)

    Returns:
        Dictionary mapping host IPs to lists of port information dicts

    Raises:
        PermissionError: If root privileges are required but not available
        RuntimeError: If nmap is not installed or scan fails
    """
    nm = nmap.PortScanner()
    timing_flag = settings.timing_templates.get(timing, "-T3")

    # Fast scan of top 100 ports with specified timing
    arguments = f"-F {timing_flag}"

    # Add min-rate for faster scanning unless in stealth mode
    if timing != TimingMode.STEALTH:
        arguments += " --min-rate 1000"

    console.print(f"[info]Running: nmap {arguments} {target}[/info]")

    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        if "requires root privileges" in str(e).lower():
            raise PermissionError(
                "SYN scan requires root privileges. Run with sudo or use -sT."
            ) from e
        if "nmap program was not found" in str(e).lower():
            raise RuntimeError(
                "nmap is not installed. Please install nmap and try again."
            ) from e
        raise RuntimeError(f"Scan failed: {e}") from e

    results: dict[str, list[dict]] = {}

    for host in nm.all_hosts():
        host_results: list[dict] = []

        # Get TCP ports
        if "tcp" in nm[host]:
            for port, port_data in nm[host]["tcp"].items():
                host_results.append(
                    {
                        "port": port,
                        "protocol": "tcp",
                        "state": port_data.get("state", "unknown"),
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                    }
                )

        # Get UDP ports if scanned
        if "udp" in nm[host]:
            for port, port_data in nm[host]["udp"].items():
                host_results.append(
                    {
                        "port": port,
                        "protocol": "udp",
                        "state": port_data.get("state", "unknown"),
                        "service": port_data.get("name", "unknown"),
                        "version": port_data.get("version", ""),
                    }
                )

        if host_results:
            results[host] = host_results

    return results
