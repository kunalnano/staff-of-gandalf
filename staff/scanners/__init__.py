"""
Scanner Modules
~~~~~~~~~~~~~~~

Collection of security scanning modules that wrap nmap and other tools.

Modules:
    - illuminate: Host discovery (nmap -sn ping sweep)
    - shadowfax: Fast port scan (nmap -F --min-rate 1000)
    - delve: Deep scan with version detection (nmap -sV -sC -A)
    - scry: OSINT (WHOIS, DNS enumeration)

"I am a servant of the Secret Fire, wielder of the flame of Anor."
"""

from staff.scanners.illuminate import discover_hosts
from staff.scanners.shadowfax import fast_scan
from staff.scanners.delve import deep_scan
from staff.scanners.scry import osint_lookup

__all__ = ["discover_hosts", "fast_scan", "deep_scan", "osint_lookup"]
