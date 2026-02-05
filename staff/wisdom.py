"""
Gandalf's Wisdom — LLM-Powered Scan Analysis
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

"I am a servant of the Secret Fire, wielder of the flame of Anor.
The dark fire will not avail you, flame of Udûn!"

Streams security insights from Claude or local LLMs,
speaking as Gandalf, directly into your terminal.

Backends:
  - claude   : Anthropic API (default, requires ANTHROPIC_API_KEY)
  - lmstudio : LM Studio on Windows workstation (OpenAI-compatible)
  - ollama   : Ollama on Windows workstation (OpenAI-compatible)
"""

import json
import os
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.console import Console

from staff.config import console, print_quote, settings


class LLMBackend(str, Enum):
    CLAUDE = "claude"
    LMSTUDIO = "lmstudio"
    OLLAMA = "ollama"


SYSTEM_PROMPT = """You are Gandalf the Grey, a wise and battle-tested security wizard analyzing network scan results from your enchanted staff.

Your task: Analyze the scan JSON and provide actionable security insights. Stay in character but be TECHNICALLY PRECISE. You are speaking to a skilled network defender.

Structure your response as follows:

## 🗺️ Realm Overview
Brief network topology summary. Identify what each host likely is (router, workstation, server, IoT device) based on ports, services, and behavior.

## ⚔️ Threat Assessment
For EACH host with open ports, analyze:
- What the service is and what version/product was detected
- Whether the configuration looks secure or concerning
- Specific attack vectors an adversary could exploit
- Script output interpretation (nmap scripts often reveal critical details)

## 🔥 Critical Findings
Prioritized list of issues that need immediate attention. Be specific:
- What's wrong
- Why it matters (real-world attack scenario)
- Exact remediation steps (commands, config changes, not vague advice)

## 🛡️ Hardening Recommendations  
Proactive steps beyond fixing current issues:
- Firewall rules to consider
- Services that should be disabled
- Network segmentation advice
- Monitoring suggestions

## 📊 Risk Score
Rate the network: CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
Justify with specific evidence from the scan.

IMPORTANT RULES:
- Reference specific ports, IPs, services, and nmap script output from the scan data
- No generic security advice — everything must be tied to what you actually found
- If you see script output (like HTTP redirects, DNS responses, fingerprints), interpret what they reveal
- Keep the Gandalf voice but never sacrifice technical accuracy for flavor
- Be concise. Every sentence should deliver value."""


def _build_user_message(scan_data: dict) -> str:
    """Build the user message with scan context."""
    return (
        f"Analyze this network scan of {scan_data.get('target', 'unknown target')}.\n"
        f"Scan timestamp: {scan_data.get('timestamp', 'unknown')}\n"
        f"Timing mode: {scan_data.get('timing_mode', 'default')}\n\n"
        f"Full scan JSON:\n```json\n{json.dumps(scan_data, indent=2)}\n```"
    )


def _print_header(backend: LLMBackend, model: str) -> None:
    """Print the wisdom header panel."""
    backend_labels = {
        LLMBackend.CLAUDE: f"☁️  Claude ({model})",
        LLMBackend.LMSTUDIO: f"🖥️  LM Studio @ Orthanc ({settings.orthanc_host})",
        LLMBackend.OLLAMA: f"🦙 Ollama @ Orthanc ({settings.orthanc_host}:{settings.ollama_port})",
    }
    label = backend_labels.get(backend, backend.value)

    console.print()
    console.print(Panel.fit(
        f"[bold bright_white]🧙 Gandalf's Wisdom — Live Analysis[/bold bright_white]\n"
        f"[dim]{label}[/dim]",
        border_style="bright_white",
        subtitle="[dim]streaming from the Palantír...[/dim]"
    ))
    console.print()


# ── Claude (Anthropic API) ─────────────────────────────────────────


def _stream_claude(scan_data: dict, model: str) -> None:
    """Stream analysis from Claude API."""
    try:
        import anthropic
    except ImportError:
        console.print(
            "[danger]The anthropic package is not installed.[/danger]\n"
            "[info]Run: pip install anthropic[/info]"
        )
        sys.exit(1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print(
            "[danger]ANTHROPIC_API_KEY not set.[/danger]\n"
            "[info]Export your key: export ANTHROPIC_API_KEY='sk-ant-...'[/info]\n"
            "[info]Or add it to your shell profile (~/.zshrc).[/info]"
        )
        sys.exit(1)

    client = anthropic.Anthropic(api_key=api_key)
    collected = ""

    with Live(
        Markdown("*The wizard peers into the Palantír...*"),
        console=console, refresh_per_second=8, vertical_overflow="visible",
    ) as live:
        with client.messages.stream(
            model=model,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _build_user_message(scan_data)}],
        ) as stream:
            for text in stream.text_stream:
                collected += text
                live.update(Markdown(collected))


# ── OpenAI-Compatible (LM Studio / Ollama) ─────────────────────────


def _stream_openai_compat(scan_data: dict, base_url: str, model: str) -> None:
    """Stream analysis from any OpenAI-compatible endpoint (LM Studio, Ollama)."""
    try:
        from openai import OpenAI
    except ImportError:
        console.print(
            "[danger]The openai package is not installed.[/danger]\n"
            "[info]Run: pip install openai[/info]"
        )
        sys.exit(1)

    # Test connectivity first
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(base_url.rstrip("/") + "/models", method="GET")
        urllib.request.urlopen(req, timeout=5)
    except (urllib.error.URLError, ConnectionRefusedError, OSError) as e:
        console.print(
            f"[danger]Cannot reach Orthanc at {base_url}[/danger]\n"
            f"[info]Error: {e}[/info]\n"
            f"[info]Check that:[/info]\n"
            f"  1. Windows workstation is on ({settings.orthanc_host})\n"
            f"  2. LM Studio / Ollama server is running\n"
            f"  3. 'Serve on Local Network' is enabled\n"
            f"  4. Windows Firewall allows the port"
        )
        sys.exit(1)

    client = OpenAI(base_url=base_url, api_key="not-needed")
    collected = ""

    with Live(
        Markdown("*The wizard consults the Palantír in Orthanc tower...*"),
        console=console, refresh_per_second=8, vertical_overflow="visible",
    ) as live:
        stream = client.chat.completions.create(
            model=model,
            max_tokens=4096,
            stream=True,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_message(scan_data)},
            ],
        )
        for chunk in stream:
            delta = chunk.choices[0].delta.content if chunk.choices[0].delta.content else ""
            if delta:
                collected += delta
                live.update(Markdown(collected))


# ── Public API ──────────────────────────────────────────────────────


def analyze_scan(
    scan_data: dict,
    model: str = "claude-sonnet-4-20250514",
    backend: LLMBackend = LLMBackend.CLAUDE,
) -> None:
    """
    Stream LLM analysis of scan results to the terminal.

    Args:
        scan_data: Parsed scan JSON dictionary
        model: Model name (Claude model or local model name)
        backend: Which LLM backend to use
    """
    _print_header(backend, model)

    if backend == LLMBackend.CLAUDE:
        _stream_claude(scan_data, model)
    elif backend == LLMBackend.LMSTUDIO:
        _stream_openai_compat(scan_data, settings.lmstudio_url, model)
    elif backend == LLMBackend.OLLAMA:
        # Ollama uses /v1 suffix for OpenAI compat mode
        _stream_openai_compat(scan_data, f"{settings.ollama_url}/v1", model)

    console.print()
    print_quote("scan_complete")


def analyze_from_file(
    json_path: Path,
    model: str = "claude-sonnet-4-20250514",
    backend: LLMBackend = LLMBackend.CLAUDE,
) -> None:
    """
    Load scan JSON from file and run LLM analysis.

    Args:
        json_path: Path to scan JSON file
        model: Model name
        backend: Which LLM backend to use
    """
    if not json_path.exists():
        console.print(f"[danger]File not found: {json_path}[/danger]")
        sys.exit(1)

    try:
        with open(json_path) as f:
            scan_data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[danger]Invalid JSON: {e}[/danger]")
        sys.exit(1)

    analyze_scan(scan_data, model, backend)
