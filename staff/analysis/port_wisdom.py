"""
Port Wisdom Knowledge Base
~~~~~~~~~~~~~~~~~~~~~~~~~~

Comprehensive mapping of common ports to risk levels and Gandalf commentary.

"A wizard is never late, nor is he early. He knows precisely what each port means."
"""

from typing import Literal, NamedTuple


class PortInfo(NamedTuple):
    """Information about a port."""
    service: str
    risk: Literal["critical", "warning", "info"]
    description: str
    gandalf_wisdom: str


# Comprehensive port knowledge base
PORT_WISDOM: dict[int, PortInfo] = {
    # Critical Risk Ports
    21: PortInfo(
        service="FTP",
        risk="critical",
        description="File Transfer Protocol - often has anonymous access enabled",
        gandalf_wisdom="FTP without encryption is like leaving the gates of Minas Tirith wide open.",
    ),
    23: PortInfo(
        service="Telnet",
        risk="critical",
        description="Unencrypted remote access - deprecated for security reasons",
        gandalf_wisdom="Telnet transmits credentials in plain text. Even Sauron could not design a more obvious trap.",
    ),
    445: PortInfo(
        service="SMB",
        risk="critical",
        description="Windows file sharing - frequent target for ransomware",
        gandalf_wisdom="SMB exposed to the internet? This is precisely how the Shadow spreads.",
    ),
    3389: PortInfo(
        service="RDP",
        risk="critical",
        description="Windows Remote Desktop - commonly brute-forced",
        gandalf_wisdom="RDP exposed? Mordor's armies have breached many realms through this gate.",
    ),
    6379: PortInfo(
        service="Redis",
        risk="critical",
        description="Redis database - often deployed without authentication",
        gandalf_wisdom="An unprotected Redis is like leaving the One Ring on display in Rivendell.",
    ),
    27017: PortInfo(
        service="MongoDB",
        risk="critical",
        description="MongoDB database - frequent source of data breaches",
        gandalf_wisdom="MongoDB without auth has caused more data breaches than Sauron had orcs.",
    ),

    # Warning Risk Ports
    22: PortInfo(
        service="SSH",
        risk="info",
        description="Secure Shell - encrypted remote access",
        gandalf_wisdom="SSH is well-guarded, but ensure strong keys are your gatekeepers.",
    ),
    25: PortInfo(
        service="SMTP",
        risk="warning",
        description="Simple Mail Transfer Protocol - can be abused for spam",
        gandalf_wisdom="An open mail relay is a beacon for spammers across Middle-earth.",
    ),
    53: PortInfo(
        service="DNS",
        risk="info",
        description="Domain Name System - essential but can leak information",
        gandalf_wisdom="DNS reveals much about a realm's structure. Guard it well.",
    ),
    80: PortInfo(
        service="HTTP",
        risk="warning",
        description="Unencrypted web traffic",
        gandalf_wisdom="HTTP without HTTPS? The Eye of Sauron sees all that passes.",
    ),
    110: PortInfo(
        service="POP3",
        risk="warning",
        description="Post Office Protocol - unencrypted email retrieval",
        gandalf_wisdom="POP3 without encryption exposes every message to prying eyes.",
    ),
    111: PortInfo(
        service="RPCbind",
        risk="warning",
        description="RPC port mapper - can expose other services",
        gandalf_wisdom="RPCbind can reveal hidden services. Keep it behind the walls.",
    ),
    135: PortInfo(
        service="MSRPC",
        risk="warning",
        description="Microsoft RPC - Windows service discovery",
        gandalf_wisdom="MSRPC exposed on the internet invites unwanted visitors.",
    ),
    139: PortInfo(
        service="NetBIOS",
        risk="warning",
        description="NetBIOS Session Service - legacy Windows networking",
        gandalf_wisdom="NetBIOS is an artifact from a less secure age. Best kept hidden.",
    ),
    143: PortInfo(
        service="IMAP",
        risk="warning",
        description="Internet Message Access Protocol - email retrieval",
        gandalf_wisdom="IMAP should always be protected by TLS encryption.",
    ),
    443: PortInfo(
        service="HTTPS",
        risk="info",
        description="Encrypted web traffic",
        gandalf_wisdom="HTTPS is the shield that guards communications. Well chosen.",
    ),
    465: PortInfo(
        service="SMTPS",
        risk="info",
        description="Secure SMTP over SSL",
        gandalf_wisdom="Encrypted mail transfer - a wise precaution.",
    ),
    993: PortInfo(
        service="IMAPS",
        risk="info",
        description="Secure IMAP over SSL",
        gandalf_wisdom="Encrypted IMAP protects the contents of messages.",
    ),
    995: PortInfo(
        service="POP3S",
        risk="info",
        description="Secure POP3 over SSL",
        gandalf_wisdom="POP3 over SSL - the proper way to retrieve mail.",
    ),
    1433: PortInfo(
        service="MSSQL",
        risk="warning",
        description="Microsoft SQL Server - should not be publicly exposed",
        gandalf_wisdom="A database exposed to the world is a treasure chest left open.",
    ),
    1521: PortInfo(
        service="Oracle",
        risk="warning",
        description="Oracle database listener",
        gandalf_wisdom="Oracle exposed? The Enemy seeks databases rich with data.",
    ),
    2049: PortInfo(
        service="NFS",
        risk="warning",
        description="Network File System - can expose sensitive files",
        gandalf_wisdom="NFS shares should be restricted. Not all should see your files.",
    ),
    3306: PortInfo(
        service="MySQL",
        risk="warning",
        description="MySQL database - should not be publicly exposed",
        gandalf_wisdom="MySQL on the internet is an invitation to dark forces.",
    ),
    5432: PortInfo(
        service="PostgreSQL",
        risk="warning",
        description="PostgreSQL database - should not be publicly exposed",
        gandalf_wisdom="PostgreSQL is powerful, but power must be protected.",
    ),
    5900: PortInfo(
        service="VNC",
        risk="warning",
        description="Virtual Network Computing - remote desktop",
        gandalf_wisdom="VNC can be weak in its encryption. Use with caution.",
    ),
    8080: PortInfo(
        service="HTTP-Proxy",
        risk="warning",
        description="Common alternative HTTP port",
        gandalf_wisdom="Alternative web ports often hide admin interfaces.",
    ),
    8443: PortInfo(
        service="HTTPS-Alt",
        risk="info",
        description="Alternative HTTPS port",
        gandalf_wisdom="An alternative secure port - acceptable, though unusual.",
    ),
    9200: PortInfo(
        service="Elasticsearch",
        risk="warning",
        description="Elasticsearch HTTP API",
        gandalf_wisdom="Elasticsearch exposed can reveal all indexed secrets.",
    ),
    11211: PortInfo(
        service="Memcached",
        risk="warning",
        description="Memcached distributed cache",
        gandalf_wisdom="Memcached without auth can be weaponized for DDoS.",
    ),

    # Home Network / Consumer Services
    1900: PortInfo(
        service="UPnP/SSDP",
        risk="warning",
        description="Universal Plug and Play - allows automatic port forwarding",
        gandalf_wisdom="UPnP opens gates from within. Any device on your network can punch holes in the firewall.",
    ),
    5000: PortInfo(
        service="AirPlay/UPnP",
        risk="info",
        description="Apple AirPlay or UPnP media streaming",
        gandalf_wisdom="AirPlay is expected within the Shire. Ensure it does not reach beyond.",
    ),
    5353: PortInfo(
        service="mDNS",
        risk="info",
        description="Multicast DNS - local service discovery (Bonjour/Avahi)",
        gandalf_wisdom="mDNS reveals the names and services of all devices nearby. Useful, but chatty.",
    ),
    7000: PortInfo(
        service="AirPlay-Video",
        risk="info",
        description="Apple AirPlay video streaming",
        gandalf_wisdom="Video streams within the realm. Harmless if kept local.",
    ),
    7100: PortInfo(
        service="AirPlay-Alt",
        risk="info",
        description="Apple AirPlay alternative port",
        gandalf_wisdom="Another AirPlay channel. Apple's birds carry many messages.",
    ),
    8008: PortInfo(
        service="Chromecast-HTTP",
        risk="info",
        description="Google Chromecast HTTP control",
        gandalf_wisdom="A Chromecast awaits commands. Only a concern if uninvited guests share the network.",
    ),
    8009: PortInfo(
        service="Chromecast-CAST",
        risk="info",
        description="Google Cast protocol",
        gandalf_wisdom="The Cast protocol. Entertainment, not danger — unless your network has strangers.",
    ),
    8200: PortInfo(
        service="MiniDLNA",
        risk="info",
        description="DLNA media server",
        gandalf_wisdom="A media library open to the local network. Keep it behind the gates.",
    ),
    9100: PortInfo(
        service="Printer-RAW",
        risk="warning",
        description="Raw network printing - no authentication required",
        gandalf_wisdom="Network printers accept jobs from anyone who asks. A minor but real risk.",
    ),
    10000: PortInfo(
        service="Webmin/NDMP",
        risk="warning",
        description="Webmin admin panel or NDMP data management",
        gandalf_wisdom="Admin panels should be behind strong authentication, not open doors.",
    ),
    49152: PortInfo(
        service="Ephemeral",
        risk="info",
        description="Dynamic/ephemeral port range (49152-65535) - typically OS-assigned",
        gandalf_wisdom="A high port, likely assigned by the OS for a transient purpose. Note it, but do not fear it.",
    ),
    49153: PortInfo(
        service="Ephemeral",
        risk="info",
        description="Dynamic/ephemeral port range",
        gandalf_wisdom="Another transient port. The OS opens these as needed.",
    ),
    49154: PortInfo(
        service="Ephemeral",
        risk="info",
        description="Dynamic/ephemeral port range",
        gandalf_wisdom="Ephemeral ports are the comings and goings of the realm. Usually benign.",
    ),
    631: PortInfo(
        service="IPP",
        risk="info",
        description="Internet Printing Protocol (CUPS)",
        gandalf_wisdom="The print server. Ensure it serves only trusted hosts.",
    ),
    548: PortInfo(
        service="AFP",
        risk="warning",
        description="Apple Filing Protocol - legacy Mac file sharing",
        gandalf_wisdom="AFP is of an older age. SMB has since taken its place. Consider disabling it.",
    ),
    62078: PortInfo(
        service="iphone-sync",
        risk="info",
        description="Apple iOS sync service (lockdownd)",
        gandalf_wisdom="An iPhone reveals itself. Expected in the Shire.",
    ),
}


def get_port_info(port: int) -> PortInfo:
    """
    Get information about a specific port.

    Args:
        port: The port number to look up

    Returns:
        PortInfo with service details and risk assessment
    """
    if port in PORT_WISDOM:
        return PORT_WISDOM[port]

    # Unknown port - provide generic info
    return PortInfo(
        service="Unknown",
        risk="info",
        description="Unknown service on this port",
        gandalf_wisdom="An unfamiliar door. Proceed with caution.",
    )


def get_dangerous_ports() -> list[int]:
    """Return list of ports considered critical risk."""
    return [port for port, info in PORT_WISDOM.items() if info.risk == "critical"]


def get_warning_ports() -> list[int]:
    """Return list of ports considered warning level."""
    return [port for port, info in PORT_WISDOM.items() if info.risk == "warning"]
