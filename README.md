# 🧙 Staff of the Grey Pilgrim

> *"All that is gold does not glitter,*
> *Not all those who wander are lost;*
> *The old that is strong does not wither,*
> *Deep roots are not reached by the frost."*

A Gandalf-themed security assessment CLI that wraps real security tools (nmap, WHOIS, DNS) and generates narrative reports written in the Grey Pilgrim's voice.

---

## ⚠️ Important Legal Notice

**This tool is designed for AUTHORIZED security testing only.**

By using this tool, you confirm that:
1. You have explicit written authorization to test the target systems
2. You understand and accept responsibility for your actions
3. You will comply with all applicable laws and regulations

*"With great power comes great responsibility."* - Not Gandalf, but still true.

---

## Prerequisites

Before wielding the Staff, ensure you have:

- **Python 3.11+** - The language of wizards
- **nmap** - The Grey Pilgrim's scrying tool
- **Root/sudo access** - Required for certain scan types (SYN scans, OS detection)
- **Network access** - To targets you are authorized to test

### Installing nmap

```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt install nmap

# RHEL/CentOS
sudo yum install nmap

# Windows
# Download from https://nmap.org/download.html
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/greypilgrim/staff.git
cd staff

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install the package
pip install -e .
```

Or use the setup script:

```bash
./init.sh
```

---

## Commands

The Staff offers six powerful commands, each named for the Grey Pilgrim's tools and allies.

### 🔮 Survey - Full Assessment Pipeline

*"The board is set, the pieces are moving."*

Run a complete assessment: discovery → scan → analysis → report.

```bash
# Full survey of a target
staff survey 192.168.1.1 --output report.md

# Stealthy survey (slower, less detectable)
staff survey 192.168.1.0/24 --stealth --output stealth_report.md

# Aggressive survey (faster, more noisy)
staff survey target.example.com --aggressive --output fast_report.md
```

### 💡 Illuminate - Host Discovery

*"I see a light in the darkness of the network."*

Discover live hosts without port scanning (nmap -sn ping sweep).

```bash
# Discover hosts on a network
staff illuminate 192.168.1.0/24

# Stealthy host discovery
staff illuminate 10.0.0.0/24 --stealth
```

### 🐴 Shadowfax - Fast Port Scan

*"Shadowfax is the lord of all horses."*

Quick scan of the most common ports (nmap -F).

```bash
# Fast scan of common ports
staff shadowfax 192.168.1.1

# Aggressive fast scan
staff shadowfax target.example.com --aggressive
```

### ⛏️ Delve - Deep Scan

*"The Dwarves delved too greedily and too deep. We shall delve carefully."*

Comprehensive scan with version detection, scripts, and OS fingerprinting.

```bash
# Deep scan specific ports
staff delve 192.168.1.1 -p 22,80,443

# Deep scan port range
staff delve target.example.com -p 1-1000

# Stealthy deep scan
staff delve 192.168.1.1 -p 22,80,443 --stealth
```

### 🔮 Scry - OSINT Lookup

*"The Mirror shows many things, and not all have yet come to pass."*

Passive reconnaissance: WHOIS and DNS enumeration.

```bash
# OSINT lookup for a domain
staff scry example.com

# Investigate a target domain
staff scry target.example.com
```

### 📜 Council - Generate Report

*"The tale is now told. May this counsel serve you well."*

Generate a report from previously saved scan JSON.

```bash
# Generate report from saved scan
staff council reports/scan_192.168.1.1_20240101_120000.json --output report.md
```

---

## Output

### JSON Results

All scans automatically save JSON results to the `reports/` directory with timestamped filenames:

```
reports/scan_192.168.1.1_20240101_120000.json
```

### Markdown Reports

Reports are generated in the "Counsel of the Grey Pilgrim" format with sections:

1. **Lay of the Land** - Network topology and discovered hosts
2. **Open Gates** - Port analysis with service details
3. **Shadows and Flames** - Vulnerabilities by severity
4. **The Wizard's Counsel** - Prioritized recommendations

---

## Timing Modes

| Mode | Flag | nmap Timing | Use Case |
|------|------|-------------|----------|
| Default | (none) | T3 | Balanced speed and stealth |
| Stealth | `--stealth` | T2 | Slower, harder to detect |
| Aggressive | `--aggressive` | T5 | Fastest, for time-critical situations |

---

## Severity Levels

The Grey Pilgrim classifies findings by severity:

| Level | Emoji | Description |
|-------|-------|-------------|
| Critical | 🔴 | *"Fly, you fools!"* - Immediate action required |
| Warning | 🟡 | *"I would not take this road..."* - Should be addressed |
| Info | 🟢 | *"The Grey Pilgrim observes..."* - Awareness items |

---

## Project Structure

```
staff/
├── staff/
│   ├── __init__.py
│   ├── cli.py              # Typer CLI entry point
│   ├── config.py           # Settings and Gandalf quotes (25+)
│   ├── scanners/
│   │   ├── illuminate.py   # Host discovery
│   │   ├── shadowfax.py    # Fast port scan
│   │   ├── delve.py        # Deep scan
│   │   └── scry.py         # OSINT (WHOIS, DNS)
│   ├── analysis/
│   │   ├── threat_assess.py # Vulnerability analysis
│   │   └── port_wisdom.py   # Port knowledge base
│   ├── reporting/
│   │   ├── council.py      # Report generator
│   │   └── templates/
│   │       └── counsel.md.j2
│   └── models/
│       └── scan_result.py  # Pydantic models
├── reports/                # Generated reports
├── pyproject.toml
└── README.md
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Format code
black staff/

# Lint
ruff check staff/

# Type check
mypy staff/
```

---

## Credits

- **nmap** - The powerful network scanner that makes this possible
- **Typer** - Beautiful CLI framework
- **Rich** - Terminal formatting that brings the grey/white theme to life
- **J.R.R. Tolkien** - For creating the Grey Pilgrim who inspires us all

---

## License

MIT License - See LICENSE for details.

---

> *"A wizard is never late, nor is he early. He scans precisely when he means to."*
>
> — Gandalf the Grey (probably)
