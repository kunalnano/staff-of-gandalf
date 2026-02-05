"""
Configuration and Settings
~~~~~~~~~~~~~~~~~~~~~~~~~~

Application settings and the Gandalf quotes database.

"The wise speak only of what they know."
"""

import random
from enum import Enum
from typing import Optional

from pydantic import BaseModel
from rich.console import Console
from rich.theme import Theme


class TimingMode(str, Enum):
    """Scan timing modes that affect nmap timing templates."""

    DEFAULT = "default"
    STEALTH = "stealth"
    AGGRESSIVE = "aggressive"


class Settings(BaseModel):
    """Application settings."""

    version: str = "0.1.0"
    app_name: str = "Staff of the Grey Pilgrim"
    reports_dir: str = "reports"

    # Default home network — "The Shire"
    home_network: str = "192.168.4.0/22"

    # Windows workstation — "Orthanc" (the tower with the Palantír)
    orthanc_host: str = "192.168.7.69"  # Windows workstation IP — update if needed
    lmstudio_port: int = 1234
    ollama_port: int = 11434
    local_model: str = "qwen3:30b-a3b"  # Default Ollama model

    # nmap timing templates
    timing_templates: dict = {
        TimingMode.DEFAULT: "-T3",
        TimingMode.STEALTH: "-T2",
        TimingMode.AGGRESSIVE: "-T5",
    }

    @property
    def lmstudio_url(self) -> str:
        return f"http://{self.orthanc_host}:{self.lmstudio_port}/v1"

    @property
    def ollama_url(self) -> str:
        return f"http://{self.orthanc_host}:{self.ollama_port}"


settings = Settings()

# Custom Rich theme with grey/white and flame colors
GANDALF_THEME = Theme(
    {
        "info": "grey70",
        "warning": "orange1",
        "danger": "red1",
        "critical": "bold red1",
        "success": "green3",
        "title": "bold white",
        "subtitle": "grey78",
        "quote": "italic grey70",
        "banner": "bold white on grey23",
        "finding.critical": "bold red1",
        "finding.warning": "bold orange1",
        "finding.info": "grey70",
        "port.open": "green3",
        "port.closed": "grey50",
        "port.filtered": "yellow3",
        "host.up": "green3",
        "host.down": "grey50",
    }
)

console = Console(theme=GANDALF_THEME)


# Banner displayed on CLI startup
BANNER = """
╭─────────────────────────────────────────────╮
│  🧙 Staff of the Grey Pilgrim v0.1.0        │
│  "All that is gold does not glitter..."     │
╰─────────────────────────────────────────────╯
"""

# Gandalf quotes database - 25+ quotes mapped to events
QUOTES = {
    "scan_start": [
        "A wizard is never late, nor is he early. He scans precisely when he means to.",
        "The journey of a thousand ports begins with a single packet.",
        "So it begins. The great scan of our time.",
        "The world is changed. I feel it in the network. I sense it in the packets.",
    ],
    "scan_complete": [
        "The board is set, the pieces are moving. We come now to the analysis.",
        "It is done. The scanning is complete.",
        "The Grey Pilgrim has finished his reconnaissance.",
        "Many that scan don't know what they'll find. Some that find don't know what it means.",
    ],
    "host_found": [
        "So you have come to me for counsel. I see hosts awakening in the darkness.",
        "A host! I see a light in the darkness of the network.",
        "There are many hosts in this realm, and this one responds.",
        "The beacon is lit! A host has answered our call.",
    ],
    "port_open": [
        "There are many doors in this realm, and some should remain shut.",
        "An open port is like an open door - you never know who might walk through.",
        "I see you've left a door unlocked. Let us see what lies beyond.",
        "Open ports are paths - some lead to treasure, others to ruin.",
    ],
    "vulnerability_found": [
        "There is only one Lord of the Ring, and he does not share power... nor patch his systems.",
        "The enemy has many spies. This vulnerability is one of them.",
        "A weakness has been found. The Shadow grows.",
        "Even the smallest vulnerability can change the course of the future.",
    ],
    "critical_finding": [
        "Fly, you fools! This vulnerability requires immediate attention.",
        "This is a critical weakness. The Balrog of security flaws.",
        "Danger! Great danger lies in this finding.",
        "You cannot pass! This vulnerability must be addressed immediately.",
    ],
    "warning_finding": [
        "I would not take this road without caution.",
        "A warning, if you will heed it. Danger may lie ahead.",
        "This path is not without risk. Proceed with wisdom.",
        "The way is treacherous. Consider this warning well.",
    ],
    "safe_finding": [
        "The Grey Pilgrim finds this acceptable, for now.",
        "This appears sound. The wizards of security would approve.",
        "A small comfort in these dark times - this is properly secured.",
        "Well done. This port is well-guarded.",
    ],
    "report_generated": [
        "The tale is now told. May this counsel serve you well.",
        "My report is complete. Read it with the wisdom it deserves.",
        "I have recorded all that I have found. Use this knowledge wisely.",
        "The Counsel of the Grey Pilgrim is committed to parchment.",
    ],
    "no_hosts_found": [
        "The world is grey, the mountains old, the hosts have all gone cold.",
        "I see nothing. The darkness is complete. No hosts respond.",
        "Empty. As empty as Moria in its abandonment.",
        "Not all who wander find hosts. None responded to our call.",
    ],
    "scan_error": [
        "Even the very wise cannot see all ends. An error has occurred.",
        "Something has gone wrong. Even wizards make mistakes.",
        "The spell has failed. We must try a different approach.",
        "An unexpected turn of events. Error encountered.",
    ],
    "permission_denied": [
        "You shall not pass... without sudo privileges.",
        "These doors require greater authority than you possess.",
        "The gate is locked. You need root powers to proceed.",
        "Insufficient privileges. The way is barred to those without authority.",
    ],
    "aggressive_mode": [
        "Do not take me for some conjurer of cheap tricks. Aggressive scanning enabled.",
        "You have chosen the path of haste. May it serve you well.",
        "Speed over stealth. Let us hope we are not detected.",
        "The fast road is chosen. Discretion is cast aside.",
    ],
    "stealth_mode": [
        "Quiet now. We move as shadows.",
        "Stealth is our ally. We proceed with caution.",
        "Like a hobbit, we shall pass unseen.",
        "Patience. The slow road is often the safest.",
    ],
    "network_timeout": [
        "I have no memory of this network responding.",
        "The darkness is too deep. The target does not answer.",
        "Time has run out. The host remains silent.",
        "Lost in the darkness of the network, our packets never returned.",
    ],
    "invalid_target": [
        "This target makes no sense. Check your spelling, young wizard.",
        "I cannot scan what does not exist.",
        "An invalid target leads nowhere. Try again.",
        "The coordinates you have given are... meaningless.",
    ],
    "dns_failure": [
        "The name servers speak not of this domain.",
        "DNS has failed us. The name cannot be resolved.",
        "This domain is unknown to the servers of names.",
        "No records exist for this name in the halls of DNS.",
    ],
    "nmap_not_found": [
        "Nmap is not installed. You lack the proper tools, young wizard.",
        "Without nmap, we are blind. Install it and return.",
        "The Grey Pilgrim requires nmap to see clearly.",
        "A wizard without nmap is like Gandalf without his staff.",
    ],
    "scan_interrupted": [
        "The scan has been interrupted. A wizard knows when to retreat.",
        "You have chosen to end this early. Perhaps wisdom guides your hand.",
        "Interrupted. Even the Grey Pilgrim respects the will of the user.",
        "The journey ends before its time. But what was found remains.",
    ],
}


def get_quote(event: str) -> str:
    """
    Get a random Gandalf quote for the given event.

    Args:
        event: The event type (e.g., 'scan_start', 'host_found')

    Returns:
        A random quote for the event, or a default message if event not found.
    """
    quotes = QUOTES.get(event)
    if quotes:
        return random.choice(quotes)
    return "The Grey Pilgrim ponders in silence..."


def print_quote(event: str, style: Optional[str] = "quote") -> None:
    """Print a quote to the console with appropriate styling."""
    quote = get_quote(event)
    console.print(f"\n[{style}]\"{quote}\"[/{style}]\n")


def print_banner() -> None:
    """Print the application banner."""
    console.print(BANNER, style="banner")


# Legal disclaimer
DISCLAIMER = """
⚠️  IMPORTANT LEGAL NOTICE ⚠️

This tool is designed for AUTHORIZED security testing only.

By using this tool, you confirm that:
1. You have explicit written authorization to test the target systems
2. You understand and accept responsibility for your actions
3. You will comply with all applicable laws and regulations

Unauthorized access to computer systems is illegal and unethical.
"With great power comes great responsibility." - Not Gandalf, but still true.
"""
