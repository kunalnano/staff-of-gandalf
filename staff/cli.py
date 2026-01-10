"""
CLI Entry Point
~~~~~~~~~~~~~~~

Typer-based CLI for Staff of the Grey Pilgrim.

"A wizard is never late, nor is he early. He scans precisely when he means to."
"""

import ipaddress
import json
import re
import signal
import sys
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


# Global flag to track if interrupted
_interrupted = False


def handle_interrupt(signum, frame):
    """Handle Ctrl+C gracefully."""
    global _interrupted
    _interrupted = True
    console.print("\n\n[warning]⚠ Scan interrupted by user.[/warning]")
    print_quote("scan_interrupted")
    console.print("[info]The wizard retreats... for now.[/info]")
    sys.exit(130)  # Standard exit code for SIGINT


# Register the signal handler
signal.signal(signal.SIGINT, handle_interrupt)


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


def validate_port_spec(ports: str) -> None:
    """
    Validate port specification string.

    Accepts formats like: "22", "80,443", "1-1000", "22,80,443,8000-9000"

    Args:
        ports: Port specification string

    Raises:
        typer.Exit: If the port specification is invalid
    """
    # Handle comma-separated parts
    parts = ports.split(",")

    for part in parts:
        part = part.strip()
        if not part:
            continue

        # Handle port ranges like "1-1000"
        if "-" in part:
            range_parts = part.split("-")
            if len(range_parts) != 2:
                console.print(
                    f"[danger]Error: Invalid port range format '{part}'. "
                    f"Use format like '1-1000'.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)

            start_str, end_str = range_parts
            try:
                start_port = int(start_str.strip())
                end_port = int(end_str.strip())
            except ValueError:
                console.print(
                    f"[danger]Error: Non-numeric port in range '{part}'. "
                    f"Ports must be numbers between 1 and 65535.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)

            # Validate port range values
            for port, label in [(start_port, "start"), (end_port, "end")]:
                if port < 1:
                    console.print(
                        f"[danger]Error: Invalid port '{port}' in range. "
                        f"Port numbers must be at least 1.[/danger]"
                    )
                    print_quote("scan_error")
                    raise typer.Exit(1)
                if port > 65535:
                    console.print(
                        f"[danger]Error: Port '{port}' out of range. "
                        f"Maximum port number is 65535.[/danger]"
                    )
                    print_quote("scan_error")
                    raise typer.Exit(1)

            if start_port > end_port:
                console.print(
                    f"[danger]Error: Invalid port range '{part}'. "
                    f"Start port must be less than or equal to end port.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)
        else:
            # Single port
            try:
                port = int(part)
            except ValueError:
                console.print(
                    f"[danger]Error: Non-numeric port '{part}'. "
                    f"Ports must be numbers between 1 and 65535.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)

            if port < 1:
                console.print(
                    f"[danger]Error: Invalid port '{port}'. "
                    f"Port numbers must be at least 1.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)
            if port > 65535:
                console.print(
                    f"[danger]Error: Port '{port}' out of range. "
                    f"Maximum port number is 65535.[/danger]"
                )
                print_quote("scan_error")
                raise typer.Exit(1)


def validate_target(target: str) -> None:
    """
    Validate target specification (IP address, hostname, or CIDR range).

    Args:
        target: Target IP, hostname, or CIDR range

    Raises:
        typer.Exit: If the target specification is invalid
    """
    # Check for CIDR notation first
    if "/" in target:
        try:
            # Try to parse as network
            ipaddress.ip_network(target, strict=False)
            return  # Valid CIDR notation
        except ValueError as e:
            console.print(
                f"[danger]Error: Invalid CIDR notation '{target}'. "
                f"{str(e)}[/danger]"
            )
            print_quote("scan_error")
            raise typer.Exit(1)

    # Check if it looks like an IP address (contains only digits and dots for IPv4)
    # or IPv6 (contains colons)
    if re.match(r'^[\d.]+$', target):
        # Looks like IPv4 - validate it
        try:
            ipaddress.ip_address(target)
            return  # Valid IP address
        except ValueError:
            console.print(
                f"[danger]Error: Invalid IP address '{target}'. "
                f"IP address octets must be between 0 and 255.[/danger]"
            )
            print_quote("scan_error")
            raise typer.Exit(1)

    if ":" in target and not target.startswith("["):
        # Looks like IPv6 - validate it
        try:
            ipaddress.ip_address(target)
            return  # Valid IPv6 address
        except ValueError:
            console.print(
                f"[danger]Error: Invalid IPv6 address '{target}'.[/danger]"
            )
            print_quote("scan_error")
            raise typer.Exit(1)

    # Otherwise treat as hostname - basic validation
    # Hostnames can contain alphanumerics, hyphens, and dots
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$'
    if not re.match(hostname_pattern, target):
        # Allow localhost and other single-word hostnames
        if target.lower() not in ['localhost']:
            console.print(
                f"[danger]Error: Invalid target '{target}'. "
                f"Target must be a valid IP address, hostname, or CIDR range.[/danger]"
            )
            print_quote("scan_error")
            raise typer.Exit(1)


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
    # Validate target before proceeding
    validate_target(target)

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
    json_output: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results to JSON file"),
    ] = None,
) -> None:
    """
    Host discovery only (nmap -sn ping sweep).

    Discovers live hosts on a network without port scanning.
    """
    # Validate target before proceeding
    validate_target(target)

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

            # Save JSON if requested
            if json_output:
                session = ScanSession(target=target, timing_mode=timing.value)
                session.illuminate_results = results
                with open(json_output, "w") as f:
                    json.dump(session.to_json_dict(), f, indent=2)
                console.print(f"\n[success]✓ JSON results saved to:[/success] {json_output}")
        else:
            print_quote("no_hosts_found")
            if json_output:
                session = ScanSession(target=target, timing_mode=timing.value)
                session.illuminate_results = []
                with open(json_output, "w") as f:
                    json.dump(session.to_json_dict(), f, indent=2)
                console.print(f"\n[success]✓ JSON results saved to:[/success] {json_output}")
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
    json_output: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results to JSON file"),
    ] = None,
) -> None:
    """
    Fast port scan only (nmap -F --min-rate 1000).

    Quick scan of the most common ports.
    """
    # Validate target before proceeding
    validate_target(target)

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

        # Save JSON if requested
        if json_output:
            session = ScanSession(target=target, timing_mode=timing.value)
            session.shadowfax_results = results if results else {}
            with open(json_output, "w") as f:
                json.dump(session.to_json_dict(), f, indent=2)
            console.print(f"\n[success]✓ JSON results saved to:[/success] {json_output}")

        if not results:
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
    json_output: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results to JSON file"),
    ] = None,
) -> None:
    """
    Deep scan with service/version detection (nmap -sV -sC -A).

    Comprehensive scan with version detection, scripts, and OS fingerprinting.
    """
    # Validate target and port specification before proceeding
    validate_target(target)
    validate_port_spec(ports)

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

        # Save JSON if requested
        if json_output:
            session = ScanSession(target=target, timing_mode=timing.value)
            session.delve_results = results if results else {}
            with open(json_output, "w") as f:
                json.dump(session.to_json_dict(), f, indent=2)
            console.print(f"\n[success]✓ JSON results saved to:[/success] {json_output}")

        if not results:
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
    json_output: Annotated[
        Optional[Path],
        typer.Option("--json", "-j", help="Save results to JSON file"),
    ] = None,
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

            # Save JSON if requested
            if json_output:
                session = ScanSession(target=domain, timing_mode="default")
                session.scry_results = results
                with open(json_output, "w") as f:
                    json.dump(session.to_json_dict(), f, indent=2)
                console.print(f"\n[success]✓ JSON results saved to:[/success] {json_output}")

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
