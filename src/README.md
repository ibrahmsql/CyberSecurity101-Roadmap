# 📁 src – Cybersecurity Tool Samples

This directory contains minimal, **educational** sample tools in multiple programming languages.  Each script demonstrates a common security task and can be expanded for real-world use.

> ⚠️  All examples are for **authorized security testing** and training only.

| Language | Tool | Purpose |
|----------|------|---------|
| Python   | `network_scan.py` | Simple Nmap wrapper for quick host discovery & port scan |
| Python   | `vt_lookup.py`    | VirusTotal file-hash reputation lookup |
| Bash     | `quick_scan.sh`   | Lightweight netcat-based port scanner |
| PowerShell | `WinEnum.ps1`   | Basic Windows enumeration (processes, services, patches) |
| Go       | `reverse_shell.go`| Cross-platform reverse shell (demo) |

Feel free to add more languages (Rust, JavaScript, etc.) and additional categories (cloud, SIEM, malware analysis, etc.) following the same pattern.

---

## Quick Start

```bash
# Example: run Python network scan
python3 python/network_scan.py 192.168.1.0/24
```

Ensure required dependencies are installed (see each script header).
