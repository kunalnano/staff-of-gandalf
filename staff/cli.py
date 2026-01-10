"""
CLI Entry Point
~~~~~~~~~~~~~~~

Typer-based CLI for Staff of the Grey Pilgrim.

"A wizard is never late, nor is he early. He scans precisely when he means to."
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from staff.config import (
    BANNER,
    DISCLAIMER,
    TimingMode,
    console,
    get_quote,
    print_quote,
    settings,
)
from staff.models.scan_result import ScanSession

app = typer.Typer(
    name="staff",
    help="🧙 Staff of the Grey Pilgrim - Gandalf-themed security assessment CLI",
    no_args_is_help=True,
    add_completion=False,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"Staff of the Grey Pilgrim v{settings.version}")
        raise typer.Exit()


def show_banner() -> None:
    """Display the application banner."""
    console.print(BANNER)


def get_timing_flag(stealth: bool, aggressive: bool) -> TimingMode:
    """Determine timing mode from flags."""
    if stealth and aggressive:
        console.print(
            "[danger]Error: Cannot use both --stealth and --aggressive[/danger]"
        )
        raise typer.Exit(1)
    if stealth:
        print_quote("stealth_mode")
        return TimingMode.STEALTH
    if aggressive:
        print_quote("aggressive_mode", style="warning")
        return TimingMode.AGGRESSIVE
    return TimingMode.DEFAULT


def save_results(session: ScanSession, target: str) -> Path:
    """Save scan results to JSON file."""
    reports_dir = Path(settings.reports_dir)
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_")
    filename = f"scan_{safe_target}_{timestamp}.json"
    filepath = reports_dir / filename

    with open(filepath, "w") as f:
        json.dump(session.to_json_dict(), f, indent=2)

    return filepath


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """
    🧙 Staff of the Grey Pilgrim

    A Gandalf-themed security assessment CLI for authorized penetration testing.

    IMPORTANT: Only use this tool against systems you have explicit authorization to test.
    """
    show_banner()


@app.command()
def survey(
    target: Annotated[str, typer.Argument(help="Target IP, hostname, or CIDR range")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output path for markdown report"),
    ] = Path("report.md"),
    stealth: Annotated[
        bool,
        typer.Option("--stealth", "-s", help="Use slower, stealthier scans (T2)"),
    ] = False,
    aggressive: Annotated[
        bool,
        typer.Option("--aggressive", "-a", help="Use fastest scans (T5)"),
    ] = False,
) -> None:
    """
    Full assessment pipeline: discovery → scan → analysis → report.

    Runs illuminate, shadowfax, delve, and generates a comprehensive report.
    """
    timing = get_timing_flag(stealth, aggressive)
    print_quote("scan_start")

    console.print(f"[title]Survey Target:[/title] {target}")
    console.print(f"[subtitle]Timing Mode:[/subtitle] {timing.value}")
    console.print(f"[subtitle]Output:[/subtitle] {output}")

    # Import scanners here to avoid circular imports
    from staff.scanners import illuminate, shadowfax, delve, scry
    from staff.analysis import threat_assess
    from staff.reporting import council

    session = ScanSession(target=target, timing_mode=timing.value)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Phase 1: Illuminate (Host Discovery)
        task = progress.add_task("[cyan]Illuminate: Discovering hosts...", total=None)
        try:
            session.illuminate_results = illuminate.discover_hosts(target, timing)
            progress.update(task, completed=True)
            if session.illuminate_results:
                print_quote("host_found")
            else:
                print_quote("no_hosts_found")
        except Exception as e:
            console.print(f"[danger]Illuminate failed: {e}[/danger]")
            print_quote("scan_error")

        # Phase 2: Shadowfax (Fast Port Scan)
        task = progress.add_task("[cyan]Shadowfax: Fast port scan...", total=None)
        try:
            session.shadowfax_results = shadowfax.fast_scan(target, timing)
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[danger]Shadowfax failed: {e}[/danger]")
            print_quote("scan_error")

        # Phase 3: Delve (Deep Scan)
        task = progress.add_task("[cyan]Delve: Deep scanning...", total=None)
        try:
            session.delve_results = delve.deep_scan(target, timing)
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[danger]Delve failed: {e}[/danger]")
            print_quote("scan_error")

        # Phase 4: Analysis
        task = progress.add_task("[cyan]Analyzing findings...", total=None)
        try:
            session.findings = threat_assess.assess_threats(session)
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[danger]Analysis failed: {e}[/danger]")

        # Phase 5: Generate Report
        task = progress.add_task("[cyan]Generating report...", total=None)
        try:
            council.generate_report(session, output)
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[danger]Report generation failed: {e}[/danger]")

    # Save JSON results
    json_path = save_results(session, target)
    console.print(f"\n[success]✓ JSON results saved to:[/success] {json_path}")
    console.print(f"[success]✓ Report generated at:[/success] {output}")

    print_quote("scan_complete")


@app.command()
def illuminate(
    target: Annotated[str, typer.Argument(help="Target IP, hostname, or CIDR range")],
    stealth: Annotated[
        bool,
        typer.Option("--stealth", "-s", help="Use slower, stealthier scans (T2)"),
    ] = False,
    aggressive: Annotated[
        bool,
        typer.Option("--aggressive", "-a", help="Use fastest scans (T5)"),
    ] = False,
) -> None:
    """
    Host discovery only (nmap -sn ping sweep).

    Discovers live hosts on a network without port scanning.
    """
    timing = get_timing_flag(stealth, aggressive)
    print_quote("scan_start")

    console.print(f"[title]Illuminate Target:[/title] {target}")

    from staff.scanners import illuminate as illuminate_scanner

    try:
        results = illuminate_scanner.discover_hosts(target, timing)
        if results:
            print_quote("host_found")
            console.print(f"\n[success]Discovered {len(results)} host(s):[/success]")
            for host in results:
                status_style = "host.up" if host.status == "up" else "host.down"
                console.print(
                    f"  [{status_style}]● {host.ip_address}[/{status_style}]"
                    + (f" ({host.hostname})" if host.hostname else "")
                )
        else:
            print_quote("no_hosts_found")
    except PermissionError:
        print_quote("permission_denied")
        console.print("[danger]Root privileges may be required for this scan.[/danger]")
    except Exception as e:
        print_quote("scan_error")
        console.print(f"[danger]Error: {e}[/danger]")


@app.command()
def shadowfax(
    target: Annotated[str, typer.Argument(help="Target IP, hostname, or CIDR range")],
    stealth: Annotated[
        bool,
        typer.Option("--stealth", "-s", help="Use slower, stealthier scans (T2)"),
    ] = False,
    aggressive: Annotated[
        bool,
        typer.Option("--aggressive", "-a", help="Use fastest scans (T5)"),
    ] = False,
) -> None:
    """
    Fast port scan only (nmap -F --min-rate 1000).

    Quick scan of the most common ports.
    """
    timing = get_timing_flag(stealth, aggressive)
    print_quote("scan_start")

    console.print(f"[title]Shadowfax Target:[/title] {target}")

    from staff.scanners import shadowfax as shadowfax_scanner

    try:
        results = shadowfax_scanner.fast_scan(target, timing)
        if results:
            print_quote("port_open")
            console.print("\n[success]Open ports found:[/success]")
            for host, ports in results.items():
                console.print(f"\n  [title]{host}[/title]")
                for port_info in ports:
                    state_style = f"port.{port_info.get('state', 'open')}"
                    console.print(
                        f"    [{state_style}]● {port_info['port']}/{port_info['protocol']}"
                        f" - {port_info.get('service', 'unknown')}[/{state_style}]"
                    )
        else:
            console.print("[info]No open ports found.[/info]")
        print_quote("scan_complete")
    except PermissionError:
        print_quote("permission_denied")
        console.print("[danger]Root privileges may be required for SYN scans.[/danger]")
    except Exception as e:
        print_quote("scan_error")
        console.print(f"[danger]Error: {e}[/danger]")


@app.command()
def delve(
    target: Annotated[str, typer.Argument(help="Target IP or hostname")],
    ports: Annotated[
        str,
        typer.Option("--ports", "-p", help="Ports to scan (e.g., 22,80,443 or 1-1000)"),
    ] = "1-1000",
    stealth: Annotated[
        bool,
        typer.Option("--stealth", "-s", help="Use slower, stealthier scans (T2)"),
    ] = False,
    aggressive: Annotated[
        bool,
        typer.Option("--aggressive", "-a", help="Use fastest scans (T5)"),
    ] = False,
) -> None:
    """
    Deep scan with service/version detection (nmap -sV -sC -A).

    Comprehensive scan with version detection, scripts, and OS fingerprinting.
    """
    timing = get_timing_flag(stealth, aggressive)
    print_quote("scan_start")

    console.print(f"[title]Delve Target:[/title] {target}")
    console.print(f"[subtitle]Ports:[/subtitle] {ports}")

    from staff.scanners import delve as delve_scanner

    try:
        results = delve_scanner.deep_scan(target, timing, ports)
        if results:
            print_quote("port_open")
            console.print("\n[success]Detailed scan results:[/success]")
            for host, data in results.items():
                console.print(f"\n  [title]{host}[/title]")
                for port_info in data.get("ports", []):
                    console.print(
                        f"    [port.open]● {port_info['port']}/{port_info['protocol']}[/port.open]"
                    )
                    if port_info.get("service"):
                        console.print(f"      Service: {port_info['service']}")
                    if port_info.get("version"):
                        console.print(f"      Version: {port_info['version']}")
        else:
            console.print("[info]No services detected.[/info]")
        print_quote("scan_complete")
    except PermissionError:
        print_quote("permission_denied")
        console.print("[danger]Root privileges required for OS detection.[/danger]")
    except Exception as e:
        print_quote("scan_error")
        console.print(f"[danger]Error: {e}[/danger]")


@app.command()
def scry(
    domain: Annotated[str, typer.Argument(help="Target domain for OSINT lookup")],
) -> None:
    """
    OSINT only: WHOIS, DNS records (A, AAAA, MX, TXT, NS, CNAME, SOA).

    Passive reconnaissance without active scanning.
    """
    print_quote("scan_start")

    console.print(f"[title]Scry Target:[/title] {domain}")

    from staff.scanners import scry as scry_scanner

    try:
        results = scry_scanner.osint_lookup(domain)
        if results:
            console.print("\n[success]OSINT Results:[/success]")

            # WHOIS data
            if results.registrar:
                console.print(f"\n  [subtitle]Registrar:[/subtitle] {results.registrar}")
            if results.creation_date:
                console.print(
                    f"  [subtitle]Created:[/subtitle] {results.creation_date}"
                )
            if results.name_servers:
                console.print(f"  [subtitle]Name Servers:[/subtitle]")
                for ns in results.name_servers:
                    console.print(f"    • {ns}")

            # DNS Records
            console.print("\n  [subtitle]DNS Records:[/subtitle]")
            for record_type, records in results.dns_records.items():
                if records:
                    console.print(f"    {record_type}:")
                    for record in records:
                        console.print(f"      • {record}")

        print_quote("scan_complete")
    except Exception as e:
        if "NXDOMAIN" in str(e) or "NoNameservers" in str(e):
            print_quote("dns_failure")
        else:
            print_quote("scan_error")
        console.print(f"[danger]Error: {e}[/danger]")


@app.command()
def council(
    scan_json: Annotated[
        Path,
        typer.Argument(help="Path to saved scan JSON file"),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output path for markdown report"),
    ] = Path("report.md"),
) -> None:
    """
    Generate report from previously saved scan JSON.

    Creates a markdown report from existing scan data.
    """
    if not scan_json.exists():
        print_quote("scan_error")
        console.print(f"[danger]File not found: {scan_json}[/danger]")
        raise typer.Exit(1)

    try:
        with open(scan_json) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print_quote("scan_error")
        console.print(f"[danger]Invalid JSON file: {e}[/danger]")
        raise typer.Exit(1)

    try:
        session = ScanSession.from_json_dict(data)
    except Exception as e:
        print_quote("scan_error")
        console.print(f"[danger]Failed to parse scan data: {e}[/danger]")
        raise typer.Exit(1)

    console.print(f"[title]Council: Generating report from[/title] {scan_json}")

    from staff.reporting import council as council_module

    try:
        council_module.generate_report(session, output)
        console.print(f"\n[success]✓ Report generated at:[/success] {output}")
        print_quote("report_generated")
    except Exception as e:
        print_quote("scan_error")
        console.print(f"[danger]Report generation failed: {e}[/danger]")
        raise typer.Exit(1)


@app.command()
def disclaimer() -> None:
    """
    Display the legal disclaimer about authorized testing.
    """
    console.print(DISCLAIMER)


if __name__ == "__main__":
    app()
