"""
Scry Scanner
~~~~~~~~~~~~

OSINT module for WHOIS and DNS enumeration.

"The Mirror shows many things, and not all have yet come to pass."
"""

from datetime import datetime
from typing import Optional

import dns.resolver
import whois

from staff.config import console
from staff.models.scan_result import ScryResult


DNS_RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


def osint_lookup(domain: str) -> ScryResult:
    """
    Perform OSINT lookups including WHOIS and DNS enumeration.

    Args:
        domain: Target domain to investigate

    Returns:
        ScryResult with WHOIS and DNS data

    Raises:
        RuntimeError: If WHOIS or DNS lookups fail completely
    """
    result = ScryResult(domain=domain)

    # Perform WHOIS lookup
    console.print(f"[info]Performing WHOIS lookup for {domain}...[/info]")
    try:
        whois_data = whois.whois(domain)
        if whois_data:
            result.whois_data = _parse_whois(whois_data)
            result.registrar = whois_data.registrar
            if whois_data.creation_date:
                # Handle both single date and list of dates
                creation = whois_data.creation_date
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    result.creation_date = creation
            if whois_data.name_servers:
                ns_list = whois_data.name_servers
                if isinstance(ns_list, str):
                    ns_list = [ns_list]
                result.name_servers = [
                    ns.lower() if isinstance(ns, str) else str(ns) for ns in ns_list
                ]
    except Exception as e:
        console.print(f"[warning]WHOIS lookup failed: {e}[/warning]")

    # Perform DNS enumeration
    console.print(f"[info]Enumerating DNS records for {domain}...[/info]")
    result.dns_records = {}

    for record_type in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = []
            for rdata in answers:
                if record_type == "MX":
                    records.append(f"{rdata.preference} {rdata.exchange}")
                elif record_type == "SOA":
                    records.append(
                        f"{rdata.mname} {rdata.rname} "
                        f"(serial: {rdata.serial}, refresh: {rdata.refresh})"
                    )
                else:
                    records.append(str(rdata))
            result.dns_records[record_type] = records
        except dns.resolver.NoAnswer:
            result.dns_records[record_type] = []
        except dns.resolver.NXDOMAIN:
            raise RuntimeError(f"Domain {domain} does not exist (NXDOMAIN)")
        except dns.resolver.NoNameservers:
            raise RuntimeError(f"No nameservers found for {domain}")
        except Exception as e:
            # Other DNS errors are non-fatal for this record type
            result.dns_records[record_type] = []

    return result


def _parse_whois(whois_data) -> dict:
    """
    Parse WHOIS data into a clean dictionary.

    Args:
        whois_data: Raw WHOIS response

    Returns:
        Dictionary with parsed WHOIS information
    """
    parsed = {}

    # Extract key fields
    fields_to_extract = [
        "domain_name",
        "registrar",
        "whois_server",
        "creation_date",
        "expiration_date",
        "updated_date",
        "status",
        "name_servers",
        "org",
        "country",
        "state",
        "city",
    ]

    for field in fields_to_extract:
        value = getattr(whois_data, field, None)
        if value:
            # Convert lists to strings for JSON serialization
            if isinstance(value, list):
                # For dates, take the first one
                if field.endswith("_date") and value:
                    value = value[0]
                    if isinstance(value, datetime):
                        value = value.isoformat()
                else:
                    value = [str(v) if isinstance(v, datetime) else v for v in value]
            elif isinstance(value, datetime):
                value = value.isoformat()
            parsed[field] = value

    return parsed
