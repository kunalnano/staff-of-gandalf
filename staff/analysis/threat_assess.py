"""
Threat Assessment Module
~~~~~~~~~~~~~~~~~~~~~~~~

Analyze scan results and flag concerns by severity.

"Even the smallest person can change the course of the future."
"""

from staff.analysis.port_wisdom import get_port_info, get_dangerous_ports
from staff.models.scan_result import Finding, ScanSession


# Known vulnerable versions (simplified - real implementation would use CVE database)
VULNERABLE_VERSIONS = {
    "openssh": ["4.", "5.", "6.", "7.0", "7.1", "7.2", "7.3", "7.4"],
    "apache": ["2.2", "2.4.0", "2.4.1", "2.4.2", "2.4.3", "2.4.4", "2.4.5"],
    "nginx": ["1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9"],
    "mysql": ["5.0", "5.1", "5.5", "5.6"],
    "postgres": ["8.", "9.0", "9.1", "9.2", "9.3"],
    "php": ["5.", "7.0", "7.1", "7.2"],
}


def assess_threats(session: ScanSession) -> list[Finding]:
    """
    Analyze scan session and identify security findings.

    Args:
        session: Complete scan session with all phases

    Returns:
        List of security findings sorted by severity
    """
    findings: list[Finding] = []

    # Assess shadowfax results (fast port scan)
    if session.shadowfax_results:
        findings.extend(_assess_port_scan(session.shadowfax_results))

    # Assess delve results (deep scan with versions)
    if session.delve_results:
        findings.extend(_assess_deep_scan(session.delve_results))

    # Sort by severity (critical first)
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order.get(f.severity, 3))

    return findings


def _assess_port_scan(results: dict) -> list[Finding]:
    """Assess results from fast port scan."""
    findings: list[Finding] = []
    dangerous_ports = get_dangerous_ports()

    for host, ports in results.items():
        for port_info in ports:
            port = port_info.get("port")
            state = port_info.get("state", "")

            if state != "open":
                continue

            port_data = get_port_info(port)

            # Critical ports
            if port in dangerous_ports:
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Critical Service Exposed: {port_data.service}",
                        description=f"Port {port} ({port_data.service}) is exposed. {port_data.description}",
                        port=port,
                        host=host,
                        recommendation=f"Consider restricting access to port {port} or disabling the service if not needed.",
                    )
                )
            elif port_data.risk == "warning":
                findings.append(
                    Finding(
                        severity="warning",
                        title=f"Service Requires Attention: {port_data.service}",
                        description=f"Port {port} ({port_data.service}) is open. {port_data.description}",
                        port=port,
                        host=host,
                        recommendation=f"Review the necessity of exposing port {port} and ensure proper security controls.",
                    )
                )

    return findings


def _assess_deep_scan(results: dict) -> list[Finding]:
    """Assess results from deep scan with version detection."""
    findings: list[Finding] = []

    for host, host_data in results.items():
        for port_info in host_data.get("ports", []):
            port = port_info.get("port")
            service = port_info.get("service", "").lower()
            product = port_info.get("product", "").lower()
            version = port_info.get("version", "")

            # Check for outdated versions
            vulnerability_finding = _check_version_vulnerability(
                host, port, service, product, version
            )
            if vulnerability_finding:
                findings.append(vulnerability_finding)

            # Check for unencrypted services
            if port in [80, 8080] and "http" in service:
                findings.append(
                    Finding(
                        severity="warning",
                        title="Unencrypted HTTP Service",
                        description=f"HTTP service on port {port} transmits data without encryption.",
                        port=port,
                        host=host,
                        recommendation="Redirect HTTP to HTTPS and enable TLS encryption.",
                    )
                )

            # Check for default/anonymous access indicators
            scripts = port_info.get("scripts", {})
            for script_name, output in scripts.items():
                if "anonymous" in output.lower():
                    findings.append(
                        Finding(
                            severity="critical",
                            title=f"Anonymous Access Detected on Port {port}",
                            description=f"Anonymous access may be enabled: {output[:200]}...",
                            port=port,
                            host=host,
                            recommendation="Disable anonymous access and require authentication.",
                        )
                    )

    return findings


def _check_version_vulnerability(
    host: str, port: int, service: str, product: str, version: str
) -> Finding | None:
    """Check if a service version is known to be vulnerable."""
    if not version:
        return None

    # Check against known vulnerable versions
    for product_name, vuln_versions in VULNERABLE_VERSIONS.items():
        if product_name in product or product_name in service:
            for vuln_ver in vuln_versions:
                if version.startswith(vuln_ver):
                    return Finding(
                        severity="critical",
                        title=f"Outdated {product_name.upper()} Version Detected",
                        description=f"{product_name} version {version} may have known vulnerabilities.",
                        port=port,
                        host=host,
                        recommendation=f"Update {product_name} to the latest stable version immediately.",
                    )

    return None
