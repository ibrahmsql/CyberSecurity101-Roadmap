#!/usr/bin/env python3
"""vt_lookup.py – VirusTotal file/hash lookup demo

Requirements:
    pip install requests
Usage:
    export VT_API_KEY="<your_api_key>"
    python3 vt_lookup.py <sha256_hash>

NOTE: VirusTotal public API is rate-limited (4 req/min). Use responsibly.
"""
import os
import sys
import requests

API_URL = "https://www.virustotal.com/api/v3/files/{}"


def get_api_key() -> str:
    key = os.getenv("VT_API_KEY")
    if not key:
        print("[!] Set VT_API_KEY environment variable.")
        sys.exit(1)
    return key


def lookup_file(file_hash: str):
    headers = {"x-apikey": get_api_key()}
    url = API_URL.format(file_hash)
    print(f"[+] Querying VirusTotal for {file_hash} …")
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code != 200:
        print(f"[!] Error {r.status_code}: {r.text}")
        return
    data = r.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    print("Detection stats:")
    for k, v in stats.items():
        print(f"  {k.capitalize():10}: {v}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 vt_lookup.py <sha256_hash>")
        sys.exit(1)
    lookup_file(sys.argv[1])
