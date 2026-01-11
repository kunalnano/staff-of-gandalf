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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box
import time
import threading

from staff.config import (
    BANNER,
    DISCLAIMER,
    TimingMode,
    console,
    get_quote,
    print_quote,
    settings,
    get_tidbit,
    PHASE_DESCRIPTIONS,
)
from staff.models.scan_result import ScanSession


class GandalfProgress:
    """
    Enhanced progress display with Gandalf tidbits.
    
    Shows a progress bar with changing wisdom tidbits during long operations.
    """
    
    def __init__(self, total_phases: int = 5):
        self.total_phases = total_phases
        self.current_phase = 0
        self.phase_names = ["illuminate", "shadowfax", "delve", "analyze", "report"]
        self.phase_status = {name: "⏳" for name in self.phase_names}
        self.current_tidbit = get_tidbit()
        self.tidbit_counter = 0
        self._stop_tidbit = False
        self._tidbit_thread = None
        
    def _rotate_tidbits(self):
        """Background thread to rotate tidbits."""
        while not self._stop_tidbit:
            time.sleep(3)  # Change tidbit every 3 seconds
            if not self._stop_tidbit:
                self.current_tidbit = get_tidbit()
                self.tidbit_counter += 1
    
    def start_tidbits(self):
        """Start the tidbit rotation thread."""
        self._stop_tidbit = False
        self._tidbit_thread = threading.Thread(target=self._rotate_tidbits, daemon=True)
        self._tidbit_thread.start()
    
    def stop_tidbits(self):
        """Stop the tidbit rotation thread."""
        self._stop_tidbit = True
        if self._tidbit_thread:
            self._tidbit_thread.join(timeout=1)
    
    def mark_phase_complete(self, phase: str):
        """Mark a phase as complete."""
        if phase in self.phase_status:
            self.phase_status[phase] = "✅"
            self.current_phase += 1
    
    def mark_phase_failed(self, phase: str):
        """Mark a phase as failed."""
        if phase in self.phase_status:
            self.phase_status[phase] = "❌"
            self.current_phase += 1
    
    def mark_phase_running(self, phase: str):
        """Mark a phase as currently running."""
        if phase in self.phase_status:
            self.phase_status[phase] = "🔮"
    
    def get_progress_display(self) -> Panel:
        """Generate the progress display panel."""
        # Build phase status line
        phase_line = " → ".join([
            f"{self.phase_status[p]} {p.capitalize()}" 
            for p in self.phase_names
        ])
        
        # Progress bar
        completed = self.current_phase
        total = self.total_phases
        bar_width = 30
        filled = int((completed / total) * bar_width) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_width - filled)
        percentage = int((completed / total) * 100) if total > 0 else 0
        
        # Build display
        content = f"""
{phase_line}

[cyan]Progress:[/cyan] [{bar}] {percentage}%

[dim italic]{self.current_tidbit}[/dim italic]
"""
        return Panel(
            content.strip(),
            title="[bold white]🧙 Scan Progress[/bold white]",
            border_style="grey50",
            padding=(0, 2),
        )


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

    # Initialize Gandalf progress tracker
    gandalf = GandalfProgress(total_phases=5)
    gandalf.start_tidbits()
    
    console.print()  # Spacing
    
    try:
        with Live(gandalf.get_progress_display(), refresh_per_second=4, console=console) as live:
            # Phase 1: Illuminate (Host Discovery)
            gandalf.mark_phase_running("illuminate")
            live.update(gandalf.get_progress_display())
            try:
                session.illuminate_results = illuminate.discover_hosts(target, timing)
                gandalf.mark_phase_complete("illuminate")
                live.update(gandalf.get_progress_display())
            except Exception as e:
                gandalf.mark_phase_failed("illuminate")
                live.update(gandalf.get_progress_display())
                console.print(f"\n[danger]Illuminate failed: {e}[/danger]")

            # Phase 2: Shadowfax (Fast Port Scan)
            gandalf.mark_phase_running("shadowfax")
            live.update(gandalf.get_progress_display())
            try:
                session.shadowfax_results = shadowfax.fast_scan(target, timing)
                gandalf.mark_phase_complete("shadowfax")
                live.update(gandalf.get_progress_display())
            except Exception as e:
                gandalf.mark_phase_failed("shadowfax")
                live.update(gandalf.get_progress_display())
                console.print(f"\n[danger]Shadowfax failed: {e}[/danger]")

            # Phase 3: Delve (Deep Scan)
            gandalf.mark_phase_running("delve")
            live.update(gandalf.get_progress_display())
            try:
                session.delve_results = delve.deep_scan(target, timing)
                gandalf.mark_phase_complete("delve")
                live.update(gandalf.get_progress_display())
            except Exception as e:
                gandalf.mark_phase_failed("delve")
                live.update(gandalf.get_progress_display())
                console.print(f"\n[danger]Delve failed: {e}[/danger]")

            # Phase 4: Analysis
            gandalf.mark_phase_running("analyze")
            live.update(gandalf.get_progress_display())
            try:
                session.findings = threat_assess.assess_threats(session)
                gandalf.mark_phase_complete("analyze")
                live.update(gandalf.get_progress_display())
            except Exception as e:
                gandalf.mark_phase_failed("analyze")
                live.update(gandalf.get_progress_display())
                console.print(f"\n[danger]Analysis failed: {e}[/danger]")

            # Phase 5: Generate Report
            gandalf.mark_phase_running("report")
            live.update(gandalf.get_progress_display())
            try:
                council.generate_report(session, output)
                gandalf.mark_phase_complete("report")
                live.update(gandalf.get_progress_display())
            except Exception as e:
                gandalf.mark_phase_failed("report")
                live.update(gandalf.get_progress_display())
                console.print(f"\n[danger]Report generation failed: {e}[/danger]")
    finally:
        gandalf.stop_tidbits()

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


@app.command()
def cheatsheet() -> None:
    """
    Quick reference for all Staff commands and options.
    """
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    # Header
    console.print()
    console.print(Panel.fit(
        "[bold]🧙 Staff of the Grey Pilgrim - Quick Reference[/bold]",
        border_style="bright_white"
    ))
    console.print()

    # Commands table
    cmd_table = Table(
        title="[bold]Commands[/bold]",
        box=box.ROUNDED,
        header_style="bold cyan",
        title_style="bold white",
        show_lines=True
    )
    cmd_table.add_column("Command", style="green", width=12)
    cmd_table.add_column("Purpose", style="white", width=35)
    cmd_table.add_column("Example", style="yellow", width=40)

    cmd_table.add_row(
        "survey",
        "Full pipeline: discover → scan → analyze → report",
        "staff survey 192.168.1.0/24 -o report.md"
    )
    cmd_table.add_row(
        "illuminate",
        "Host discovery (ping sweep)",
        "staff illuminate 10.0.0.0/24"
    )
    cmd_table.add_row(
        "shadowfax",
        "Fast port scan (top 100 ports)",
        "staff shadowfax 192.168.1.1"
    )
    cmd_table.add_row(
        "delve",
        "Deep scan (versions, scripts, OS)",
        "staff delve 192.168.1.1 -p 22,80,443"
    )
    cmd_table.add_row(
        "scry",
        "OSINT: WHOIS + DNS enumeration",
        "staff scry example.com"
    )
    cmd_table.add_row(
        "council",
        "Generate report from saved JSON",
        "staff council scan.json -o report.md"
    )
    console.print(cmd_table)
    console.print()

    # Flags table
    flags_table = Table(
        title="[bold]Common Flags[/bold]",
        box=box.ROUNDED,
        header_style="bold cyan",
        title_style="bold white"
    )
    flags_table.add_column("Flag", style="green", width=18)
    flags_table.add_column("Effect", style="white", width=50)

    flags_table.add_row("--stealth, -s", "Slower scans (nmap T2) - evade detection")
    flags_table.add_row("--aggressive, -a", "Fastest scans (nmap T5) - speed over stealth")
    flags_table.add_row("--output, -o FILE", "Save markdown report to FILE")
    flags_table.add_row("--json, -j FILE", "Save raw JSON results to FILE")
    flags_table.add_row("--ports, -p SPEC", "Port spec: 22,80,443 or 1-1000 or 22,80,8000-9000")
    console.print(flags_table)
    console.print()

    # Workflows panel
    workflows = """[bold cyan]Quick Recon:[/bold cyan]
  staff scry target.com && staff illuminate target.com

[bold cyan]Standard Assessment:[/bold cyan]
  staff survey 192.168.1.0/24 -o network_report.md

[bold cyan]Targeted Deep Dive:[/bold cyan]
  staff shadowfax 10.0.0.5 -j quick.json
  staff delve 10.0.0.5 -p 22,80,443,3306,5432 -j deep.json
  staff council deep.json -o final_report.md

[bold cyan]Stealth Mode:[/bold cyan]
  staff survey 10.0.0.0/24 --stealth -o stealth_report.md

[bold cyan]Fast & Loud:[/bold cyan]
  staff survey 192.168.1.1 --aggressive -o quick_report.md"""

    console.print(Panel(
        workflows,
        title="[bold]Common Workflows[/bold]",
        border_style="bright_white",
        padding=(1, 2)
    ))
    console.print()

    # Dangerous ports reference
    ports_table = Table(
        title="[bold]High-Risk Ports (Auto-Flagged)[/bold]",
        box=box.ROUNDED,
        header_style="bold red",
        title_style="bold white"
    )
    ports_table.add_column("Port", style="red", width=8)
    ports_table.add_column("Service", style="white", width=12)
    ports_table.add_column("Risk", style="yellow", width=45)

    ports_table.add_row("21", "FTP", "Unencrypted, often anonymous access")
    ports_table.add_row("23", "Telnet", "Unencrypted remote shell - deprecated")
    ports_table.add_row("445", "SMB", "Ransomware favorite, lateral movement")
    ports_table.add_row("3389", "RDP", "Brute-force target, BlueKeep vuln")
    ports_table.add_row("6379", "Redis", "Often no auth, data exfil risk")
    ports_table.add_row("27017", "MongoDB", "Often no auth, massive breach source")
    console.print(ports_table)
    console.print()

    # Footer
    console.print("[dim]Run 'staff disclaimer' before any assessment.[/dim]")
    console.print("[dim]JSON output saved to ./reports/ by default.[/dim]")
    console.print()


if __name__ == "__main__":
    app()
