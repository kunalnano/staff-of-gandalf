"""
Council Report Generator
~~~~~~~~~~~~~~~~~~~~~~~~

Generate markdown reports from scan data using Jinja2 templates.

"The tale is now told. May this counsel serve you well."
"""

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from staff.config import get_quote
from staff.models.scan_result import ScanSession


def generate_report(session: ScanSession, output_path: Path) -> None:
    """
    Generate a markdown report from scan session data.

    Args:
        session: Complete scan session with results
        output_path: Path to write the markdown report

    Raises:
        RuntimeError: If template rendering fails
    """
    # Get the template directory
    template_dir = Path(__file__).parent / "templates"

    # Set up Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Load the template
    template = env.get_template("counsel.md.j2")

    # Prepare context data
    context = _prepare_context(session)

    # Render the template
    report_content = template.render(**context)

    # Write the report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report_content)


def _prepare_context(session: ScanSession) -> dict:
    """
    Prepare context data for template rendering.

    Args:
        session: Scan session data

    Returns:
        Dictionary of context variables for the template
    """
    # Separate findings by severity
    critical_findings = [f for f in session.findings if f.severity == "critical"]
    warning_findings = [f for f in session.findings if f.severity == "warning"]
    info_findings = [f for f in session.findings if f.severity == "info"]

    # Count statistics
    total_hosts = 0
    total_ports = 0
    hosts_data = []

    if session.illuminate_results:
        total_hosts = len(session.illuminate_results)
        hosts_data = session.illuminate_results

    # Process port data
    ports_by_host = {}
    if session.shadowfax_results:
        for host, ports in session.shadowfax_results.items():
            ports_by_host[host] = ports
            total_ports += len([p for p in ports if p.get("state") == "open"])

    if session.delve_results:
        for host, data in session.delve_results.items():
            if host not in ports_by_host:
                ports_by_host[host] = data.get("ports", [])
            else:
                # Merge with more detailed data
                ports_by_host[host] = data.get("ports", [])
            total_ports = max(
                total_ports,
                sum(len([p for p in data.get("ports", []) if p.get("state") == "open"])
                    for data in session.delve_results.values())
            )

    # Get quotes
    context = {
        "title": "Counsel of the Grey Pilgrim",
        "target": session.target,
        "timestamp": session.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "timing_mode": session.timing_mode,
        # Statistics
        "total_hosts": total_hosts,
        "total_open_ports": total_ports,
        "total_findings": len(session.findings),
        "critical_count": len(critical_findings),
        "warning_count": len(warning_findings),
        "info_count": len(info_findings),
        # Data sections
        "hosts": hosts_data,
        "ports_by_host": ports_by_host,
        "findings": session.findings,
        "critical_findings": critical_findings,
        "warning_findings": warning_findings,
        "info_findings": info_findings,
        # OSINT data
        "scry_results": session.scry_results,
        # Quotes
        "opening_quote": get_quote("scan_complete"),
        "closing_quote": get_quote("report_generated"),
        # Utilities
        "now": datetime.now(),
    }

    return context
