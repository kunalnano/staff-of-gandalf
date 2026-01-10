"""
Port Wisdom Knowledge Base
~~~~~~~~~~~~~~~~~~~~~~~~~~

Comprehensive database of port information, risk levels, and Gandalf commentary.

"The wise speak only of what they know."
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class PortInfo:
    """Information about a port and its security implications."""

    port: int
    service: str
    risk: str  # "critical", "warning", "info"
    description: str
    commentary: str  # Gandalf-style commentary


# Comprehensive port knowledge base
PORT_WISDOM: dict[int, PortInfo] = {
    # Critical Risk Ports
    21: PortInfo(
        port=21,
        service="FTP",
        risk="critical",
        description="File Transfer Protocol - unencrypted file transfer",
        commentary="An ancient protocol, unencrypted and often with anonymous access. "
        "The Shadow seeks easy prey through such doors.",
    ),
    23: PortInfo(
        port=23,
        service="Telnet",
        risk="critical",
        description="Telnet - unencrypted remote access",
        commentary="Telnet sends all secrets in the clear. A relic of darker ages when "
        "security was but a dream. Close this gate immediately.",
    ),
    445: PortInfo(
        port=445,
        service="SMB",
        risk="critical",
        description="Server Message Block - Windows file sharing",
        commentary="The SMB port is a favorite path for the servants of darkness. "
        "Ransomware and worms spread through it like wildfire. Guard it well!",
    ),
    3389: PortInfo(
        port=3389,
        service="RDP",
        risk="critical",
        description="Remote Desktop Protocol - Windows remote access",
        commentary="Remote Desktop exposed to the world? A beacon for brute force attacks. "
        "The enemy never sleeps, and neither do their password crackers.",
    ),
    6379: PortInfo(
        port=6379,
        service="Redis",
        risk="critical",
        description="Redis in-memory data store",
        commentary="Redis without authentication is an open treasure chest. "
        "Many have lost their data to such carelessness.",
    ),
    27017: PortInfo(
        port=27017,
        service="MongoDB",
        risk="critical",
        description="MongoDB database",
        commentary="MongoDB without auth? The halls of data breaches echo with "
        "the cries of those who made this mistake.",
    ),
    # Warning Risk Ports
    22: PortInfo(
        port=22,
        service="SSH",
        risk="info",
        description="Secure Shell - encrypted remote access",
        commentary="SSH is the proper way to traverse the network. "
        "Ensure strong keys and disable password authentication.",
    ),
    25: PortInfo(
        port=25,
        service="SMTP",
        risk="warning",
        description="Simple Mail Transfer Protocol",
        commentary="Mail servers can be abused for spam. "
        "Ensure proper configuration to prevent relay abuse.",
    ),
    53: PortInfo(
        port=53,
        service="DNS",
        risk="info",
        description="Domain Name System",
        commentary="The realm of names. DNS is essential, but beware of "
        "zone transfer attacks and cache poisoning.",
    ),
    80: PortInfo(
        port=80,
        service="HTTP",
        risk="warning",
        description="Hypertext Transfer Protocol - unencrypted web",
        commentary="Unencrypted web traffic? In this age, all sites should use HTTPS. "
        "The enemy can see all that passes through plain HTTP.",
    ),
    110: PortInfo(
        port=110,
        service="POP3",
        risk="warning",
        description="Post Office Protocol v3 - email retrieval",
        commentary="POP3 without TLS exposes email credentials. "
        "Use POP3S (port 995) instead.",
    ),
    111: PortInfo(
        port=111,
        service="rpcbind",
        risk="warning",
        description="RPC Port Mapper",
        commentary="RPCbind can reveal services to attackers. "
        "Restrict access unless truly needed.",
    ),
    135: PortInfo(
        port=135,
        service="MSRPC",
        risk="warning",
        description="Microsoft RPC Endpoint Mapper",
        commentary="Windows RPC can be exploited for enumeration and attacks. "
        "Block from external access.",
    ),
    139: PortInfo(
        port=139,
        service="NetBIOS",
        risk="warning",
        description="NetBIOS Session Service",
        commentary="NetBIOS leaks information about the Windows network. "
        "Block it at the perimeter.",
    ),
    143: PortInfo(
        port=143,
        service="IMAP",
        risk="warning",
        description="Internet Message Access Protocol",
        commentary="IMAP without TLS exposes email. Use IMAPS (port 993) instead.",
    ),
    443: PortInfo(
        port=443,
        service="HTTPS",
        risk="info",
        description="HTTP Secure - encrypted web traffic",
        commentary="HTTPS is the shield of the web. Ensure your certificates are valid "
        "and your TLS configuration is strong.",
    ),
    465: PortInfo(
        port=465,
        service="SMTPS",
        risk="info",
        description="SMTP over SSL",
        commentary="Encrypted mail submission. This is the proper way.",
    ),
    512: PortInfo(
        port=512,
        service="rexec",
        risk="critical",
        description="Remote Execution",
        commentary="Remote execution without modern authentication? "
        "A backdoor from ancient times. Seal it!",
    ),
    513: PortInfo(
        port=513,
        service="rlogin",
        risk="critical",
        description="Remote Login",
        commentary="rlogin trusts by IP address. The enemy can spoof such trust. Close it.",
    ),
    514: PortInfo(
        port=514,
        service="rsh/syslog",
        risk="warning",
        description="Remote Shell or Syslog",
        commentary="rsh is dangerously insecure. If this is syslog, ensure it's properly secured.",
    ),
    993: PortInfo(
        port=993,
        service="IMAPS",
        risk="info",
        description="IMAP over SSL",
        commentary="Encrypted email retrieval. This is acceptable.",
    ),
    995: PortInfo(
        port=995,
        service="POP3S",
        risk="info",
        description="POP3 over SSL",
        commentary="Encrypted email retrieval. This is acceptable.",
    ),
    1433: PortInfo(
        port=1433,
        service="MSSQL",
        risk="warning",
        description="Microsoft SQL Server",
        commentary="Database ports should not face the outer world. "
        "Protect your data stores behind firewalls.",
    ),
    1521: PortInfo(
        port=1521,
        service="Oracle",
        risk="warning",
        description="Oracle Database",
        commentary="Oracle exposed? The data within is precious. Shield it from prying eyes.",
    ),
    2049: PortInfo(
        port=2049,
        service="NFS",
        risk="warning",
        description="Network File System",
        commentary="NFS can expose file systems to the world. "
        "Configure exports carefully.",
    ),
    3306: PortInfo(
        port=3306,
        service="MySQL",
        risk="warning",
        description="MySQL Database",
        commentary="MySQL should be behind a firewall, not greeting the world. "
        "Database ports exposed are invitations to disaster.",
    ),
    5432: PortInfo(
        port=5432,
        service="PostgreSQL",
        risk="warning",
        description="PostgreSQL Database",
        commentary="PostgreSQL exposed? The data elephant should be safely corralled.",
    ),
    5900: PortInfo(
        port=5900,
        service="VNC",
        risk="warning",
        description="Virtual Network Computing",
        commentary="VNC exposed? Screen sharing should be protected. "
        "Ensure strong authentication is in place.",
    ),
    6000: PortInfo(
        port=6000,
        service="X11",
        risk="warning",
        description="X Window System",
        commentary="X11 exposed can leak display contents. Tunnel through SSH instead.",
    ),
    8080: PortInfo(
        port=8080,
        service="HTTP-alt",
        risk="info",
        description="Alternative HTTP port",
        commentary="An alternate web port. Often used for proxies or development. "
        "Verify this is intentional.",
    ),
    8443: PortInfo(
        port=8443,
        service="HTTPS-alt",
        risk="info",
        description="Alternative HTTPS port",
        commentary="An alternate HTTPS port. Common for web applications. "
        "Ensure TLS is properly configured.",
    ),
    9200: PortInfo(
        port=9200,
        service="Elasticsearch",
        risk="critical",
        description="Elasticsearch HTTP API",
        commentary="Elasticsearch without authentication? Many kingdoms of data have "
        "fallen through this gap in their defenses.",
    ),
    11211: PortInfo(
        port=11211,
        service="Memcached",
        risk="critical",
        description="Memcached",
        commentary="Memcached exposed can be used for DDoS amplification. "
        "A weapon in the wrong hands.",
    ),
}


def get_port_info(port: int) -> Optional[PortInfo]:
    """
    Get information about a specific port.

    Args:
        port: Port number to look up

    Returns:
        PortInfo if known, None otherwise
    """
    return PORT_WISDOM.get(port)


def get_port_risk(port: int) -> str:
    """
    Get the risk level for a port.

    Args:
        port: Port number to assess

    Returns:
        Risk level ("critical", "warning", or "info")
    """
    info = PORT_WISDOM.get(port)
    if info:
        return info.risk
    return "info"  # Unknown ports default to info


def get_port_commentary(port: int) -> str:
    """
    Get Gandalf's commentary on a port.

    Args:
        port: Port number

    Returns:
        Commentary string or default message
    """
    info = PORT_WISDOM.get(port)
    if info:
        return info.commentary
    return "This port is not in my ancient tomes. Investigate further."
