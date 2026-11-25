#!/usr/bin/env python3
"""Validate synthetic QEMU probe output without claiming GNSS runtime."""
import argparse
from pathlib import Path

MARKERS = ("GLIBC_2_24", "PTHREAD_TLS", "DLOPEN_DLSYM", "R800_GLIBC_QEMU_PROBE")

def valid_log(log):
    expected = [key + "=PASS" for key in MARKERS]
    actual = [line for line in log.splitlines()
              if line.partition("=")[0].strip() in MARKERS]
    return actual == expected

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("log", type=Path)
    args = p.parse_args()
    if not valid_log(args.log.read_text(encoding="utf-8", errors="replace")):
        p.exit(1, "QEMU probe markers missing, contradictory, duplicated or out of order\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
