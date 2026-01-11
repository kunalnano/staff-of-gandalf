"""
Council Report Generator
~~~~~~~~~~~~~~~~~~~~~~~~

Generate markdown reports styled as "Counsel of the Grey Pilgrim".

"The tale is now told. May this counsel serve you well."
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from staff.config import get_quote
from staff.models.scan_result import ScanSession


def generate_report(session: ScanSession, output_path: Path) -> None:
    """
    Generate a markdown report from scan session.

    Args:
        session: Complete scan session with all phases
        output_path: Path where markdown report will be saved
    """
    # Get the templates directory
    templates_dir = Path(__file__).parent / "templates"

    # Create Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Load the template
    template = env.get_template("counsel.md.j2")

    # Prepare port data - merge shadowfax and delve results
    ports_by_host: dict[str, list[dict]] = {}

    if session.shadowfax_results:
        for host, ports in session.shadowfax_results.items():
            if host not in ports_by_host:
                ports_by_host[host] = []
            ports_by_host[host].extend(ports)

    if session.delve_results:
        for host, data in session.delve_results.items():
            if host not in ports_by_host:
                ports_by_host[host] = []
            # Add delve ports (with more detail)
            for port_info in data.get("ports", []):
                # Check if port already exists from shadowfax
                existing = next(
                    (p for p in ports_by_host[host] if p.get("port") == port_info.get("port")),
                    None
                )
                if existing:
                    # Merge version info from delve
                    existing.update({
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", ""),
                    })
                else:
                    ports_by_host[host].append(port_info)

    # Render the template
    content = template.render(
        session=session,
        hosts=session.illuminate_results or [],
        ports_by_host=ports_by_host,
        findings=session.findings,
        scry=session.scry_results,
        closing_quote=get_quote("report_generated"),
    )

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the report
    with open(output_path, "w") as f:
        f.write(content)
