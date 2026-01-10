"""
Threat Assessment Engine
~~~~~~~~~~~~~~~~~~~~~~~~

Analyze scan results and generate security findings.

"Even the very wise cannot see all ends."
"""

from typing import Optional

from staff.analysis.port_wisdom import PORT_WISDOM, get_port_info
from staff.models.scan_result import Finding, ScanSession


# Known vulnerable versions (simplified - real implementation would use CVE database)
KNOWN_VULNERABLE_VERSIONS = {
    "apache": {
        "2.2": "critical",  # Apache 2.2.x is end of life
        "2.4.49": "critical",  # Path traversal vulnerability
        "2.4.50": "critical",  # Path traversal vulnerability
    },
    "openssh": {
        "7.": "warning",  # Older OpenSSH versions
        "6.": "critical",  # Very old OpenSSH
        "5.": "critical",
    },
    "mysql": {
        "5.5": "warning",  # End of life
        "5.6": "warning",  # End of life
    },
    "nginx": {
        "1.16": "warning",  # Older version
        "1.14": "warning",
    },
    "proftpd": {
        "1.3.3": "critical",  # Known backdoor vulnerability
    },
    "vsftpd": {
        "2.3.4": "critical",  # Famous backdoor version
    },
}


# Critical ports that should never be exposed
CRITICAL_PORTS = {21, 23, 445, 512, 513, 514, 3389, 6379, 9200, 11211, 27017}

# Ports that require encryption but often don't have it
UNENCRYPTED_SERVICES = {
    21: ("FTP", "SFTP (port 22) or FTPS"),
    23: ("Telnet", "SSH (port 22)"),
    80: ("HTTP", "HTTPS (port 443)"),
    110: ("POP3", "POP3S (port 995)"),
    143: ("IMAP", "IMAPS (port 993)"),
    25: ("SMTP", "SMTPS (port 465) or STARTTLS"),
}


def assess_threats(session: ScanSession) -> list[Finding]:
    """
    Analyze scan results and generate security findings.

    Args:
        session: Complete scan session with results from all phases

    Returns:
        List of Finding objects sorted by severity
    """
    findings: list[Finding] = []

    # Analyze shadowfax results (fast port scan)
    if session.shadowfax_results:
        findings.extend(_assess_port_scan(session.shadowfax_results))

    # Analyze delve results (deep scan with versions)
    if session.delve_results:
        findings.extend(_assess_deep_scan(session.delve_results))

    # Analyze OSINT results
    if session.scry_results:
        findings.extend(_assess_osint(session.scry_results))

    # Sort findings by severity (critical first)
    severity_order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_order.get(f.severity, 3))

    return findings


def _assess_port_scan(results: dict[str, list[dict]]) -> list[Finding]:
    """Assess findings from port scan results."""
    findings: list[Finding] = []

    for host, ports in results.items():
        for port_info in ports:
            port_num = port_info.get("port", 0)
            state = port_info.get("state", "")
            service = port_info.get("service", "unknown")

            if state != "open":
                continue

            # Check for critical ports
            if port_num in CRITICAL_PORTS:
                port_data = get_port_info(port_num)
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Critical port {port_num} ({service}) exposed",
                        description=port_data.description if port_data else f"Port {port_num} is a critical service",
                        port=port_num,
                        host=host,
                        recommendation=port_data.commentary if port_data else "Close this port immediately",
                    )
                )

            # Check for unencrypted services
            elif port_num in UNENCRYPTED_SERVICES:
                service_name, alternative = UNENCRYPTED_SERVICES[port_num]
                findings.append(
                    Finding(
                        severity="warning",
                        title=f"Unencrypted {service_name} service on port {port_num}",
                        description=f"{service_name} transmits data in plaintext, exposing credentials and data to interception.",
                        port=port_num,
                        host=host,
                        recommendation=f"Replace with encrypted alternative: {alternative}",
                    )
                )

            # Add info findings for known services
            elif port_num in PORT_WISDOM:
                port_data = PORT_WISDOM[port_num]
                if port_data.risk == "warning":
                    findings.append(
                        Finding(
                            severity="warning",
                            title=f"{port_data.service} service exposed on port {port_num}",
                            description=port_data.description,
                            port=port_num,
                            host=host,
                            recommendation=port_data.commentary,
                        )
                    )

    return findings


def _assess_deep_scan(results: dict[str, dict]) -> list[Finding]:
    """Assess findings from deep scan results with version detection."""
    findings: list[Finding] = []

    for host, data in results.items():
        ports = data.get("ports", [])

        for port_info in ports:
            port_num = port_info.get("port", 0)
            service = port_info.get("service", "").lower()
            product = port_info.get("product", "").lower()
            version = port_info.get("version", "")
            scripts = port_info.get("scripts", {})

            # Check for vulnerable versions
            for product_name, vuln_versions in KNOWN_VULNERABLE_VERSIONS.items():
                if product_name in service or product_name in product:
                    for vuln_ver, severity in vuln_versions.items():
                        if version and version.startswith(vuln_ver):
                            findings.append(
                                Finding(
                                    severity=severity,
                                    title=f"Vulnerable {product_name} version {version} detected",
                                    description=f"Version {version} of {product_name} has known vulnerabilities.",
                                    port=port_num,
                                    host=host,
                                    recommendation=f"Update {product_name} to the latest stable version immediately.",
                                )
                            )
                            break

            # Check for anonymous FTP
            if service == "ftp" and "ftp-anon" in scripts:
                anon_output = scripts.get("ftp-anon", "")
                if "Anonymous FTP login allowed" in anon_output:
                    findings.append(
                        Finding(
                            severity="critical",
                            title="Anonymous FTP access enabled",
                            description="The FTP server allows anonymous login, potentially exposing files.",
                            port=port_num,
                            host=host,
                            recommendation="Disable anonymous FTP access unless specifically required.",
                        )
                    )

            # Check for default credentials indicators
            for script_name, output in scripts.items():
                if "default" in output.lower() and "credential" in output.lower():
                    findings.append(
                        Finding(
                            severity="critical",
                            title=f"Possible default credentials on {service}",
                            description=f"Script {script_name} indicates default credentials may be in use.",
                            port=port_num,
                            host=host,
                            recommendation="Change default credentials immediately.",
                        )
                    )

    return findings


def _assess_osint(scry_result) -> list[Finding]:
    """Assess findings from OSINT results."""
    findings: list[Finding] = []

    # Check for SPF record
    txt_records = scry_result.dns_records.get("TXT", [])
    has_spf = any("v=spf1" in str(r) for r in txt_records)

    if not has_spf:
        findings.append(
            Finding(
                severity="warning",
                title="No SPF record found",
                description="Domain lacks SPF (Sender Policy Framework) record for email authentication.",
                port=None,
                host=scry_result.domain,
                recommendation="Add an SPF record to prevent email spoofing.",
            )
        )

    # Check for DMARC record
    has_dmarc = any("v=DMARC1" in str(r) for r in txt_records)
    if not has_dmarc:
        findings.append(
            Finding(
                severity="warning",
                title="No DMARC record found",
                description="Domain lacks DMARC record for email authentication policy.",
                port=None,
                host=scry_result.domain,
                recommendation="Add a DMARC record to protect against email spoofing.",
            )
        )

    return findings
