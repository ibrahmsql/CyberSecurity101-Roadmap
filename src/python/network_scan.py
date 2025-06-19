#!/usr/bin/env python3
"""network_scan.py – Minimal Nmap wrapper

Usage:
    python3 network_scan.py 192.168.1.0/24 -p 1-1000

Requires:
    • Nmap installed and in PATH
    • Python 3.7+
"""
import argparse
import subprocess
import shutil
import sys
from datetime import datetime


def check_nmap() -> str:
    """Return path to nmap binary or exit."""
    nmap = shutil.which("nmap")
    if not nmap:
        print("[!] Nmap not found. Install it first.")
        sys.exit(1)
    return nmap


def run_scan(target: str, ports: str):
    nmap_path = check_nmap()
    cmd = [nmap_path, "-sS", "-Pn", "-p", ports, target]
    print(f"[+] Running: {' '.join(cmd)}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[!] Nmap error: {exc.stderr}")
        sys.exit(1)
    duration = datetime.now() - start
    print(f"[+] Scan completed in {duration}")
    print(result.stdout)


def main():
    parser = argparse.ArgumentParser(description="Quick TCP SYN scan using Nmap")
    parser.add_argument("target", help="Target IP, range, or CIDR block")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (default: 1-1024)")
    args = parser.parse_args()
    run_scan(args.target, args.ports)


if __name__ == "__main__":
    main()
