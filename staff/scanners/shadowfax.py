"""
Shadowfax Scanner
~~~~~~~~~~~~~~~~~

Fast port scan via nmap -F --min-rate 1000.

"Shadowfax. Show us the meaning of haste."
"""

import nmap

from staff.config import TimingMode, console, settings


def fast_scan(
    target: str,
    timing: TimingMode = TimingMode.DEFAULT,
) -> dict[str, list[dict]]:
    """
    Perform fast port scan of common ports.

    Args:
        target: IP address or hostname to scan
        timing: Scan timing mode (default, stealth, aggressive)

    Returns:
        Dictionary mapping host IPs to list of port information

    Raises:
        PermissionError: If root privileges are required but not available
        RuntimeError: If nmap is not installed or scan fails
    """
    nm = nmap.PortScanner()
    timing_flag = settings.timing_templates.get(timing, "-T3")

    # Fast scan of top 100 ports with minimum rate
    arguments = f"-F --min-rate 1000 {timing_flag}"

    console.print(f"[info]Running: nmap {arguments} {target}[/info]")

    try:
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        if "requires root privileges" in str(e).lower():
            raise PermissionError(
                "SYN scan requires root privileges. Run with sudo."
            ) from e
        if "nmap program was not found" in str(e).lower():
            raise RuntimeError(
                "nmap is not installed. Please install nmap and try again."
            ) from e
        raise RuntimeError(f"Scan failed: {e}") from e

    results: dict[str, list[dict]] = {}

    for host in nm.all_hosts():
        host_data = nm[host]
        ports: list[dict] = []

        # Get TCP ports
        if "tcp" in host_data:
            for port, port_data in host_data["tcp"].items():
                ports.append(
                    {
                        "port": port,
                        "protocol": "tcp",
                        "state": port_data.get("state", "unknown"),
                        "service": port_data.get("name", "unknown"),
                    }
                )

        # Get UDP ports if available
        if "udp" in host_data:
            for port, port_data in host_data["udp"].items():
                ports.append(
                    {
                        "port": port,
                        "protocol": "udp",
                        "state": port_data.get("state", "unknown"),
                        "service": port_data.get("name", "unknown"),
                    }
                )

        if ports:
            results[host] = ports

    return results
