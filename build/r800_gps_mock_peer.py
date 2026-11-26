#!/usr/bin/env python3
"""Bounded host-side UNIX socket acceptance client for synthetic GPS HAL."""
import argparse
import json
from pathlib import Path
import re
import socket
import time

FIX = b"FIX 31 12.50000000 -34.25000000 100.00 1.500 90.00 5.00 1700000000000"
START = (b"STATUS 1", FIX, b"NMEA 1700000000000 $GPGGA,MOCK*00")
LIMIT = 256 * 1024


def wait_log(log, pattern, count=1, timeout=5):
    until = time.monotonic() + timeout
    while True:
        if log.exists():
            with log.open("rb") as stream:
                raw = stream.read(LIMIT+1)
            if len(raw) > LIMIT:
                raise ValueError("Oversized daemon log")
            if sum(re.fullmatch(pattern, line) is not None for line in raw.splitlines()) >= count:
                return
        if time.monotonic() >= until:
            raise ValueError("Missing daemon marker: " + repr(pattern))
        time.sleep(0.02)


class Peer:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.pending = b""
        try:
            self.sock.connect(str(path))
        except BaseException:
            self.sock.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.sock.close()

    def send(self, data):
        self.sock.sendall(data)

    def expect(self, *lines):
        for expected in lines:
            while b"\n" not in self.pending:
                chunk = self.sock.recv(512)
                if not chunk:
                    raise ValueError("Unexpected socket EOF")
                self.pending += chunk
                if len(self.pending) > 1024:
                    raise ValueError("Oversized socket frame")
            actual, self.pending = self.pending.split(b"\n", 1)
            if actual != expected:
                raise ValueError("Unexpected socket frame: " + repr(actual))

    def silent(self):
        if self.pending:
            raise ValueError("Unexpected buffered frame")
        self.sock.settimeout(0.15)
        try:
            if self.sock.recv(512) == b"":
                raise ValueError("Unexpected socket EOF")
            raise ValueError("Unexpected frame before complete command")
        except socket.timeout:
            pass
        finally:
            self.sock.settimeout(5)

    def eof(self):
        if self.pending or self.sock.recv(512) != b"":
            raise ValueError("Expected disconnect without further frames")


def exercise(path, log):
    wait_log(log, rb"listening on /opt/usr/r800dev/gps\.sock")
    with Peer(path) as p:
        p.send(b"ST")
        p.silent()
        p.send(b"ART\nSTART\nTIME 1700000000123\nLOC 12.5 -34.25 25\n")
        p.expect(*START)
        wait_log(log, rb"inject_time 1700000000123 ref [0-9]+ unc 1000 -> 0")
        wait_log(log, rb"inject_location \(android\) acc 25 -> 0")
        p.send(b"STOP\nSTOP\nSTART\n")
        p.expect(b"STATUS 2", *START)
        p.silent()
    wait_log(log, b"client gone", 1)
    with Peer(path) as p:
        p.send(b"START\n")
        p.expect(*START)
        p.send(b"\0")
        p.eof()
    wait_log(log, b"client gone", 2)
    for count, invalid in ((3, b"X"*511), (4, b"LOC 91 0 25\n")):
        with Peer(path) as p:
            p.send(invalid)
            p.eof()
        wait_log(log, b"client gone", count)
    with Peer(path) as p:
        p.send(b"START\nSTOP\n")
        p.expect(*START, b"STATUS 2")
        p.silent()
    wait_log(log, b"client gone", 5)
    return {"status": "MOCK_DAEMON_SOCKET_MATCH", "connections": 5,
            "synthetic_only": True, "vendor_abi_verified": False,
            "gnss_runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = exercise(args.socket, args.log)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "problems": [str(exc)], "safe_to_flash": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "MOCK_DAEMON_SOCKET_MATCH" else 2


if __name__ == "__main__":
    raise SystemExit(main())
