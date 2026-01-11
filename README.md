# 🧙 Staff of the Grey Pilgrim

> _"A wizard is never late, nor is he early. He scans precisely when he means to."_

A Gandalf-themed security assessment CLI that wraps real security tools (nmap, whois, DNS) and generates narrative reports written in Gandalf's voice.

## Installation

```bash
# Clone the repository
git clone https://github.com/gandalf/staff.git
cd staff

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .
```

## Prerequisites

- Python 3.11 or higher
- nmap installed and available in PATH
- Root/sudo access for certain scan types

## Commands

### Survey - Full Assessment Pipeline

> _"So it begins. The great scan of our time."_

```bash
staff survey <target> --output report.md [--stealth] [--aggressive]
```

Runs the complete pipeline: discovery → scan → analysis → report.

### Illuminate - Host Discovery

> _"I see hosts awakening in the darkness."_

```bash
staff illuminate <target> [--stealth] [--aggressive]
```

Discovers live hosts using nmap ping sweep.

### Shadowfax - Fast Port Scan

> _"Shadowfax. Show us the meaning of haste."_

```bash
staff shadowfax <target> [--stealth] [--aggressive]
```

Quick scan of the most common ports.

### Delve - Deep Scan

> _"The Dwarves delved too greedily and too deep. We shall delve carefully."_

```bash
staff delve <target> -p <ports> [--stealth] [--aggressive]
```

Comprehensive scan with version detection, scripts, and OS fingerprinting.

### Scry - OSINT Lookup

> _"The Mirror shows many things, and not all have yet come to pass."_

```bash
staff scry <domain>
```

WHOIS lookups and DNS record enumeration.

### Council - Report Generation

> _"The tale is now told. May this counsel serve you well."_

```bash
staff council <scan_json> --output report.md
```

Generate markdown report from previously saved scan data.

## Timing Modes

| Mode       | Flag           | nmap Timing | Description                |
| ---------- | -------------- | ----------- | -------------------------- |
| Default    | (none)         | T3          | Balanced speed and stealth |
| Stealth    | `--stealth`    | T2          | Slower, stealthier scans   |
| Aggressive | `--aggressive` | T5          | Fastest scans              |

## Example Workflows

### Quick Reconnaissance

```bash
staff scry example.com
staff illuminate 192.168.1.0/24
```

### Standard Assessment

```bash
staff survey 192.168.1.0/24 -o network_report.md
```

### Targeted Deep Dive

```bash
staff shadowfax 10.0.0.5 -j quick.json
staff delve 10.0.0.5 -p 22,80,443 -j deep.json
staff council deep.json -o final_report.md
```

## Legal Disclaimer

> _"With great power comes great responsibility."_

This tool is designed for **AUTHORIZED security testing only**. By using this tool, you confirm that:

1. You have explicit written authorization to test the target systems
2. You understand and accept responsibility for your actions
3. You will comply with all applicable laws and regulations

Unauthorized access to computer systems is illegal and unethical.

## License

MIT License

---

_"All that is gold does not glitter, not all those who wander are lost..."_
