#!/usr/bin/env bash
# quick_scan.sh – Minimal port scanner using /dev/tcp (bash ≥4) or nc
# Usage:
#   ./quick_scan.sh 192.168.1.1 1 1024

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <target-ip> <start-port> <end-port>" >&2
  exit 1
fi

TARGET=$1
START=$2
END=$3

command -v nc >/dev/null 2>&1 && USE_NC=1 || USE_NC=0

echo "[+] Scanning $TARGET ports $START-$END"
for ((p=START; p<=END; p++)); do
  if [[ $USE_NC -eq 1 ]]; then
    nc -z -w1 "$TARGET" "$p" 2>/dev/null && echo "Port $p open"
  else
    (echo >/dev/tcp/$TARGET/$p) >/dev/null 2>&1 && echo "Port $p open"
  fi
Done
