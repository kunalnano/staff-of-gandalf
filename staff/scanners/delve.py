"""
Delve Scanner
~~~~~~~~~~~~~

Deep scan with service/version detection (nmap -sV -sC -A).

"The Dwarves delved too greedily and too deep. We shall delve carefully."
"""

from typing import Optional

import nmap

from staff.config import TimingMode, console, settings


def deep_scan(
    target: str,
    timing: TimingMode = TimingMode.DEFAULT,
    ports: str = "1-1000",
) -> dict[str, dict]:
    """
    Perform deep scan with version detection and script scanning.

    Args:
        target: IP address or hostname to scan
        timing: Scan timing mode (default, stealth, aggressive)
        ports: Port specification (e.g., "22,80,443" or "1-1000")

    Returns:
        Dictionary mapping host IPs to detailed scan results

    Raises:
        PermissionError: If root privileges are required but not available
        RuntimeError: If nmap is not installed or scan fails
    """
    nm = nmap.PortScanner()
    timing_flag = settings.timing_templates.get(timing, "-T3")

    # Deep scan with version detection, script scanning, and OS detection
    arguments = f"-sV -sC -A {timing_flag} -p {ports}"

    console.print(f"[info]Running: nmap {arguments} {target}[/info]")
    console.print("[info]This may take a while...[/info]")

    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        if "requires root privileges" in str(e).lower():
            raise PermissionError(
                "OS detection requires root privileges. Run with sudo."
            ) from e
        if "nmap program was not found" in str(e).lower():
            raise RuntimeError(
                "nmap is not installed. Please install nmap and try again."
            ) from e
        raise RuntimeError(f"Scan failed: {e}") from e

    results: dict[str, dict] = {}

    for host in nm.all_hosts():
        host_data = nm[host]
        host_result: dict = {
            "hostname": None,
            "ports": [],
            "os": [],
            "scripts": {},
        }

        # Get hostname
        if "hostnames" in host_data and host_data["hostnames"]:
            for hn in host_data["hostnames"]:
                if hn.get("name"):
                    host_result["hostname"] = hn["name"]
                    break

        # Get OS detection results
        if "osmatch" in host_data:
            for osmatch in host_data["osmatch"]:
                host_result["os"].append(
                    {
                        "name": osmatch.get("name", "Unknown"),
                        "accuracy": osmatch.get("accuracy", "0"),
                    }
                )

        # Get TCP ports with detailed info
        if "tcp" in host_data:
            for port, port_data in host_data["tcp"].items():
                port_info = {
                    "port": port,
                    "protocol": "tcp",
                    "state": port_data.get("state", "unknown"),
                    "service": port_data.get("name", "unknown"),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "scripts": {},
                }

                # Get script results for this port
                if "script" in port_data:
                    port_info["scripts"] = port_data["script"]

                host_result["ports"].append(port_info)

        # Get UDP ports with detailed info
        if "udp" in host_data:
            for port, port_data in host_data["udp"].items():
                port_info = {
                    "port": port,
                    "protocol": "udp",
                    "state": port_data.get("state", "unknown"),
                    "service": port_data.get("name", "unknown"),
                    "product": port_data.get("product", ""),
                    "version": port_data.get("version", ""),
                    "extrainfo": port_data.get("extrainfo", ""),
                    "scripts": {},
                }

                if "script" in port_data:
                    port_info["scripts"] = port_data["script"]

                host_result["ports"].append(port_info)

        # Get host-level script results
        if "hostscript" in host_data:
            for script in host_data["hostscript"]:
                host_result["scripts"][script["id"]] = script.get("output", "")

        results[host] = host_result

    return results
