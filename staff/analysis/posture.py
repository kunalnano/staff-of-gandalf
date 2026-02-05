"""
Security Posture Scoring Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Deterministic security posture score based on scan findings.
No LLM required — pure rule-based assessment.

"The board is set, the pieces are moving. Let us see how well-guarded this realm truly is."
"""

from dataclasses import dataclass, field
from typing import Literal

from staff.analysis.port_wisdom import get_port_info, PORT_WISDOM
from staff.models.scan_result import Finding, ScanSession


@dataclass
class PostureCategory:
    """Scored category within the overall posture assessment."""

    name: str
    score: int  # 0-100
    weight: float  # how much this category matters
    summary: str
    details: list[str] = field(default_factory=list)


@dataclass
class PostureReport:
    """Complete security posture assessment."""

    overall_score: int  # 0-100
    grade: str  # A-F
    verdict: str  # Gandalf's one-liner
    categories: list[PostureCategory] = field(default_factory=list)
    topology: dict = field(default_factory=dict)  # network topology insights


# Grade thresholds
GRADE_MAP = [
    (90, "A", "The White Council approves. This realm is well-defended."),
    (80, "B", "A sturdy defense, though some cracks show in the wall."),
    (70, "C", "Passable, but the Enemy probes for exactly these weaknesses."),
    (55, "D", "Troubling gaps. The shadow grows where vigilance fades."),
    (0, "F", "The gates stand open and the watchtower is unmanned. Act now."),
]

# Ports that indicate a gateway/router device
GATEWAY_INDICATORS = {53, 80, 67, 68, 1900, 5353}

# Ports that indicate IoT or consumer devices
IOT_INDICATORS = {5000, 7000, 7100, 8008, 8009, 8443, 49152, 49153, 49154}

# Encrypted equivalents
ENCRYPTION_PAIRS = {
    80: 443,    # HTTP → HTTPS
    21: 990,    # FTP → FTPS
    23: 22,     # Telnet → SSH
    25: 465,    # SMTP → SMTPS
    110: 995,   # POP3 → POP3S
    143: 993,   # IMAP → IMAPS
}


def assess_posture(session: ScanSession) -> PostureReport:
    """
    Calculate a deterministic security posture score from scan results.

    Evaluates five categories:
    1. Attack Surface  — How many doors are open?
    2. Critical Exposure — Any known-dangerous services?
    3. Encryption Posture — Are unencrypted services present?
    4. Version Hygiene — Are services running outdated software?
    5. Network Topology — Segmentation and gateway hardening

    Returns:
        PostureReport with overall score, grade, and per-category breakdown.
    """
    categories = [
        _score_attack_surface(session),
        _score_critical_exposure(session),
        _score_encryption(session),
        _score_version_hygiene(session),
        _score_topology(session),
    ]

    # Weighted average
    total_weight = sum(c.weight for c in categories)
    if total_weight == 0:
        overall = 100
    else:
        overall = int(sum(c.score * c.weight for c in categories) / total_weight)

    overall = max(0, min(100, overall))

    # Determine grade
    grade = "F"
    verdict = GRADE_MAP[-1][2]
    for threshold, g, v in GRADE_MAP:
        if overall >= threshold:
            grade = g
            verdict = v
            break

    topology = _build_topology(session)

    return PostureReport(
        overall_score=overall,
        grade=grade,
        verdict=verdict,
        categories=categories,
        topology=topology,
    )



def _all_open_ports(session: ScanSession) -> dict[str, list[int]]:
    """Extract all open ports per host from scan results."""
    host_ports: dict[str, list[int]] = {}

    if session.shadowfax_results:
        for host, ports in session.shadowfax_results.items():
            if host not in host_ports:
                host_ports[host] = []
            for p in ports:
                if p.get("state") == "open":
                    host_ports[host].append(p["port"])

    if session.delve_results:
        for host, data in session.delve_results.items():
            if host not in host_ports:
                host_ports[host] = []
            for p in data.get("ports", []):
                if p.get("state") == "open":
                    port_num = p["port"]
                    if port_num not in host_ports[host]:
                        host_ports[host].append(port_num)

    return host_ports


def _score_attack_surface(session: ScanSession) -> PostureCategory:
    """Score based on total open ports across all hosts."""
    host_ports = _all_open_ports(session)
    total_open = sum(len(ports) for ports in host_ports.values())
    host_count = len(host_ports)

    details = []
    details.append(f"{host_count} host(s) with {total_open} total open port(s)")

    for host, ports in host_ports.items():
        details.append(f"  {host}: {len(ports)} open — {', '.join(str(p) for p in sorted(ports))}")

    # Scoring: fewer open ports = better
    # Home network: 0-5 open ports is normal, 6-15 is notable, 16+ is concerning
    if total_open <= 3:
        score = 100
    elif total_open <= 6:
        score = 90
    elif total_open <= 10:
        score = 75
    elif total_open <= 20:
        score = 55
    else:
        score = max(20, 55 - (total_open - 20) * 2)

    if total_open == 0:
        summary = "No open ports detected. Either well-locked or scan was limited."
    elif total_open <= 5:
        summary = "Minimal attack surface. Only essential services exposed."
    elif total_open <= 10:
        summary = "Moderate attack surface. Review whether all services are necessary."
    else:
        summary = "Broad attack surface. Many doors stand open to the network."

    return PostureCategory(
        name="Attack Surface",
        score=score,
        weight=0.20,
        summary=summary,
        details=details,
    )



def _score_critical_exposure(session: ScanSession) -> PostureCategory:
    """Score based on presence of known-dangerous services."""
    host_ports = _all_open_ports(session)
    details = []

    critical_count = 0
    warning_count = 0

    for host, ports in host_ports.items():
        for port in ports:
            info = get_port_info(port)
            if info.risk == "critical":
                critical_count += 1
                details.append(f"🔴 {host}:{port} — {info.service}: {info.gandalf_wisdom}")
            elif info.risk == "warning":
                warning_count += 1
                details.append(f"🟡 {host}:{port} — {info.service}: {info.gandalf_wisdom}")

    # Scoring: criticals hurt a lot, warnings hurt some
    score = 100 - (critical_count * 25) - (warning_count * 8)
    score = max(0, min(100, score))

    if critical_count == 0 and warning_count == 0:
        summary = "No known-dangerous services detected."
    elif critical_count == 0:
        summary = f"{warning_count} service(s) warrant attention but nothing immediately critical."
    else:
        summary = f"{critical_count} critical service(s) exposed. Immediate review required."

    return PostureCategory(
        name="Critical Exposure",
        score=score,
        weight=0.30,
        summary=summary,
        details=details,
    )


def _score_encryption(session: ScanSession) -> PostureCategory:
    """Score based on encrypted vs unencrypted service ratio."""
    host_ports = _all_open_ports(session)
    details = []

    unencrypted = 0
    has_encrypted_alt = 0
    total_checked = 0

    for host, ports in host_ports.items():
        port_set = set(ports)
        for plain_port, secure_port in ENCRYPTION_PAIRS.items():
            if plain_port in port_set:
                total_checked += 1
                if secure_port in port_set:
                    has_encrypted_alt += 1
                    details.append(
                        f"✓ {host}:{plain_port} has encrypted alternative :{secure_port}"
                    )
                else:
                    unencrypted += 1
                    details.append(
                        f"✗ {host}:{plain_port} ({get_port_info(plain_port).service}) — no encrypted alternative detected"
                    )

    if total_checked == 0:
        score = 100
        summary = "No encryption-sensitive services detected."
    elif unencrypted == 0:
        score = 100
        summary = "All services with encryption alternatives are covered."
    else:
        ratio = unencrypted / total_checked
        score = int(100 * (1 - ratio))
        summary = f"{unencrypted} of {total_checked} service(s) lack encrypted alternatives."

    return PostureCategory(
        name="Encryption Posture",
        score=score,
        weight=0.20,
        summary=summary,
        details=details,
    )



def _score_version_hygiene(session: ScanSession) -> PostureCategory:
    """Score based on detected software versions and known vulnerabilities."""
    details = []
    outdated_count = 0
    unknown_count = 0
    checked_count = 0

    if session.delve_results:
        for host, data in session.delve_results.items():
            for p in data.get("ports", []):
                service = p.get("service", "")
                product = p.get("product", "")
                version = p.get("version", "")
                port = p.get("port", 0)

                if not service and not product:
                    continue

                checked_count += 1

                if not version:
                    unknown_count += 1
                    details.append(
                        f"? {host}:{port} — {product or service}: version unknown"
                    )
                else:
                    # Check against known vulnerable versions
                    from staff.analysis.threat_assess import VULNERABLE_VERSIONS

                    is_vuln = False
                    for prod_name, vuln_versions in VULNERABLE_VERSIONS.items():
                        if prod_name in product.lower() or prod_name in service.lower():
                            for vv in vuln_versions:
                                if version.startswith(vv):
                                    is_vuln = True
                                    break

                    if is_vuln:
                        outdated_count += 1
                        details.append(
                            f"✗ {host}:{port} — {product} {version}: known vulnerable version"
                        )
                    else:
                        details.append(
                            f"✓ {host}:{port} — {product} {version}: no known issues"
                        )

    if checked_count == 0:
        score = 85  # no version data = can't verify, slight penalty
        summary = "No version information available. Run a deep scan (delve) for version detection."
    elif outdated_count == 0 and unknown_count == 0:
        score = 100
        summary = "All detected versions appear current."
    elif outdated_count == 0:
        score = 85 - (unknown_count * 3)
        summary = f"{unknown_count} service(s) with unknown versions. Cannot verify patch status."
    else:
        score = max(0, 100 - (outdated_count * 30) - (unknown_count * 3))
        summary = f"{outdated_count} outdated version(s) detected. Update immediately."

    score = max(0, min(100, score))

    return PostureCategory(
        name="Version Hygiene",
        score=score,
        weight=0.15,
        summary=summary,
        details=details,
    )



def _score_topology(session: ScanSession) -> PostureCategory:
    """Score based on network topology and device role analysis."""
    host_ports = _all_open_ports(session)
    details = []
    host_count = len(session.illuminate_results or [])
    demerits = 0

    gateway_hosts = []
    iot_hosts = []

    for host, ports in host_ports.items():
        port_set = set(ports)

        # Detect gateways
        gateway_overlap = port_set & GATEWAY_INDICATORS
        if len(gateway_overlap) >= 2:
            gateway_hosts.append(host)
            details.append(f"🏰 {host} — Likely gateway/router (ports: {', '.join(str(p) for p in sorted(gateway_overlap))})")

            # Gateway-specific checks
            if 80 in port_set and 443 not in port_set:
                demerits += 10
                details.append(f"  ⚠ Router admin on HTTP only (no HTTPS detected)")
            if 1900 in port_set:
                demerits += 8
                details.append(f"  ⚠ UPnP enabled — can be exploited for port forwarding and amplification attacks")
            if 53 in port_set:
                details.append(f"  ✓ DNS resolver active (expected for gateway)")

        # Detect IoT-like devices
        iot_overlap = port_set & IOT_INDICATORS
        if iot_overlap:
            iot_hosts.append(host)
            services = [f"{p}/{get_port_info(p).service}" for p in sorted(iot_overlap)]
            details.append(f"📱 {host} — Consumer/IoT services: {', '.join(services)}")

    # Scoring based on findings
    score = 100

    if host_count == 0:
        score = 50
        details.append("No hosts discovered. Scan may have been too narrow or hosts are filtered.")
    elif host_count <= 5:
        details.append(f"Small network ({host_count} hosts). Typical home topology.")
    elif host_count <= 20:
        details.append(f"Medium network ({host_count} hosts). Consider network segmentation.")
        demerits += 5
    else:
        details.append(f"Large network ({host_count} hosts). Segmentation and access controls are critical.")
        demerits += 15

    # Check if all hosts are on same subnet (no segmentation)
    if host_count > 3 and not gateway_hosts:
        demerits += 10
        details.append("No clear gateway detected. Verify scan scope includes the router.")

    score = max(0, score - demerits)

    if demerits == 0:
        summary = "Network topology looks clean for a home environment."
    elif demerits <= 10:
        summary = "Minor topology concerns. Review gateway configuration."
    else:
        summary = "Significant topology issues. Gateway hardening and segmentation needed."

    return PostureCategory(
        name="Network Topology",
        score=score,
        weight=0.15,
        summary=summary,
        details=details,
    )



def _build_topology(session: ScanSession) -> dict:
    """Build a topology summary for report rendering."""
    host_ports = _all_open_ports(session)
    hosts_info = []

    for host_result in (session.illuminate_results or []):
        ip = host_result.ip_address
        ports = host_ports.get(ip, [])
        port_set = set(ports)

        # Classify device role
        gateway_overlap = port_set & GATEWAY_INDICATORS
        iot_overlap = port_set & IOT_INDICATORS

        if len(gateway_overlap) >= 2:
            role = "Gateway/Router"
            icon = "🏰"
        elif iot_overlap:
            role = "Consumer Device"
            icon = "📱"
        elif 22 in port_set or 3389 in port_set:
            role = "Workstation/Server"
            icon = "💻"
        elif ports:
            role = "Network Host"
            icon = "🖥️"
        else:
            role = "Unknown"
            icon = "❓"

        services = []
        for p in sorted(ports):
            info = get_port_info(p)
            services.append({"port": p, "service": info.service, "risk": info.risk})

        hosts_info.append({
            "ip": ip,
            "hostname": host_result.hostname,
            "mac": host_result.mac_address,
            "role": role,
            "icon": icon,
            "services": services,
            "open_ports": len(ports),
        })

    return {
        "host_count": len(hosts_info),
        "hosts": hosts_info,
    }
