#!/usr/bin/env python3
"""yara_scan.py – Directory scan with YARA rules

Requires:
    pip install yara-python
Usage:
    python3 yara_scan.py /path/to/rules.yar /target/dir
"""
import sys
import pathlib
import yara


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 yara_scan.py <rules.yar> <target_dir>")
        sys.exit(1)
    rule_path = sys.argv[1]
    target_dir = pathlib.Path(sys.argv[2])
    if not target_dir.is_dir():
        print("Target directory not found")
        sys.exit(1)

    rules = yara.compile(filepath=rule_path)
    for file in target_dir.rglob('*'):
        if file.is_file():
            matches = rules.match(filepath=str(file))
            if matches:
                print(f"[MATCH] {file} -> {[m.rule for m in matches]}")


if __name__ == '__main__':
    main()
