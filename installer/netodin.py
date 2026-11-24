#!/usr/bin/env python3
"""
NetOdin Python Flasher for Samsung Galaxy Watch / Tizen devices.
Reverse-engineered from NetOdin3.exe (Samsung LOKE over TCP port 13579).

Supports macOS (Apple Silicon & Intel) and Linux natively without Wine or Windows.
"""

import sys
import os
import re
import socket
import struct
import tarfile
import hashlib
import time
import argparse
import r800_safety
import r800_geometry
import r800_recovery_audit

# Protocol Constants
ODIN_PORT = 13579
CHUNK_SIZE = 131072       # 128 KB streaming block
WINDOW_SIZE = 31457280    # 30 MB window (0x1E00000) - NetOdin3 standard window (240 * 128 KB)

CMD_SETUP = 100         # 0x64
CMD_PIT = 101           # 0x65
CMD_FILE_TRANSFER = 102 # 0x66
CMD_SESSION_END = 103   # 0x67

# No hardcoded PIT fallback is ever permitted for a flash operation.


def build_control_packet(cmd: int, sub: int, data=None, str1: str = "", str2: str = "") -> bytes:
    """Builds a 1024-byte Samsung Odin control packet."""
    pkt = bytearray(1024)
    struct.pack_into("<II", pkt, 0, cmd, sub)
    if data:
        for idx, val in enumerate(data):
            struct.pack_into("<I", pkt, 8 + idx * 4, val & 0xFFFFFFFF)
    if str1:
        s1_bytes = str1.encode("latin1")[:127]
        pkt[44 : 44 + len(s1_bytes)] = s1_bytes
    if str2:
        s2_bytes = str2.encode("latin1")[:31]
        pkt[172 : 172 + len(s2_bytes)] = s2_bytes
    return bytes(pkt)


def send_control_packet(sock: socket.socket, cmd: int, sub: int, data=None, str1: str = "", str2: str = "", expect_resp: bool = True):
    """Sends a 1024-byte control packet and optionally reads the 8-byte ACK."""
    pkt = build_control_packet(cmd, sub, data, str1, str2)
    sock.sendall(pkt)
    if not expect_resp:
        return (0, 0)
    resp = recv_exact(sock, 8)
    ack_cmd, ack_status = struct.unpack("<II", resp)
    if ack_cmd != cmd:
        raise IOError(f"Unexpected Odin ACK command {ack_cmd}, expected {cmd}")
    return (ack_cmd, ack_status)


def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Reads exactly `length` bytes from a socket."""
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            raise ConnectionResetError(f"Socket closed unexpectedly while waiting for {length - len(buf)} bytes.")
        buf.extend(chunk)
    return bytes(buf)


def require_transfer_success(status: int, phase: str) -> None:
    """An unknown nonzero transfer status must never be treated as success.

    Unlike CMD_SETUP, these data-transfer acknowledgements do not encode a
    protocol version in their status field.
    """
    if status != 0:
        raise IOError(f"Odin {phase} failed or returned unknown status: {status:#010x}")


def read_image_chunk(stream, expected_bytes: int, filename: str) -> bytes:
    """Abort immediately on a short read instead of committing partial data.

    Premature EOF in the old nested streaming loops could result in zero
    progress and repeated transfer windows.
    """
    if expected_bytes <= 0:
        raise ValueError("Cannot read a nonpositive image chunk")
    chunk = stream.read(expected_bytes)
    if chunk is None or len(chunk) != expected_bytes:
        raise IOError(
            f"Short image read for {filename}: expected {expected_bytes} bytes, "
            f"got {0 if chunk is None else len(chunk)}; transfer aborted")
    return chunk


def format_progress(prefix: str, current: int, total: int, start_time: float):
    elapsed = max(time.time() - start_time, 0.001)
    speed_mb = (current / (1024 * 1024)) / elapsed
    pct = (current / total) * 100
    bar_len = 30
    filled = int(bar_len * current // total)
    bar = "=" * filled + ">" + " " * (bar_len - filled - 1) if filled < bar_len else "=" * bar_len
    sys.stdout.write(f"\r  {prefix:18s} [{bar}] {pct:5.1f}% ({current/1024/1024:6.1f}/{total/1024/1024:6.1f} MB) @ {speed_mb:5.1f} MB/s")
    sys.stdout.flush()


def flash_ap_package(
    ap_path: str,
    host: str = "0.0.0.0",
    port: int = ODIN_PORT,
    auto_reboot: bool = True,
    *,
    combination_path: str | None = None,
):
    print("=" * 72)
    print("  NetOdin Python Flasher (Samsung Galaxy Watch SM-R800)")
    print("=" * 72)

    if not os.path.isfile(ap_path):
        print(f"[-] Error: File not found: {ap_path}")
        sys.exit(1)

    # A package's MD5/filename/PIT checks alone do not guard the bootloader.
    # Require and compare the combination reference before binding a socket,
    # even when this function is called directly rather than through main().
    if not combination_path:
        raise r800_safety.SafetyError(
            "A local SM-R800 combination reference is REQUIRED before any "
            "flashing. Use --combination-reference or --preflight-only. "
            "A match does not prove Samsung provenance or device safety.")
    print("[*] Offline firmware/recovery reference check (no device connection yet)...")
    r800_recovery_audit.audit_release(ap_path, combination_path)
    print("[*] Strict SM-R800 firmware preflight passed (NOT flash-safety proof).")

    # 2. Inspect AP Tar file members (skip .pit table files from partition flash list)
    print(f"[*] Analyzing firmware package: {os.path.basename(ap_path)}")
    tar_obj = tarfile.open(ap_path, "r:")
    members = r800_safety.validate_archive(tar_obj)
    total_payload = sum(m.size for m in members)
    print(f"  [+] Found {len(members)} partitions to flash (Total: {total_payload / 1024 / 1024:.2f} MB):")
    for m in members:
        print(f"      - {m.name:22s} : {m.size:10d} bytes ({m.size / 1024 / 1024:6.2f} MB)")

    # 3. Bind TCP Server
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print("\n" + "-" * 72)
    print(f"[*] TCP Server listening on {host}:{port}")
    print("[*] INSTRUCTIONS:")
    print("  1. Put Galaxy Watch in 'Download (Wireless)' AP Mode:")
    print("     - Hold Power button ~10s until 'Rebooting...'")
    print("     - Quickly tap Power 3x -> Highlight 'Download (Wireless)' -> Long-press")
    print("     - Rapidly double-press Power to switch to 'Access Point: SM-R800'")
    print("  2. Connect your Mac/Linux Wi-Fi to 'SM-R800'")
    print("  3. Waiting for connection from watch...")
    print("-" * 72)

    srv.settimeout(120)
    try:
        sock, client_addr = srv.accept()
    except socket.timeout as exc:
        srv.close()
        tar_obj.close()
        raise TimeoutError("No Odin connection after 120 s. Check Wi-Fi AP IP, "
                           "inbound TCP/13579 and other devices joining the AP.") from exc
    print(f"[+] Watch connected from {client_addr[0]}:{client_addr[1]}!")
    sock.settimeout(300.0)  # 5 min timeout
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    try:
        # Step 1: Handshake (ODIN -> LOKE)
        print("[*] Handshaking: sending 'ODIN'...")
        sock.sendall(b"ODIN")
        resp = recv_exact(sock, 4)
        if resp != b"LOKE":
            raise ValueError(f"Handshake failed! Expected 'LOKE', got {resp!r}")
        print("[+] Handshake acknowledged: received 'LOKE'!")

        # Step 2: Initialization (Cmd 100, Sub 0)
        print("[*] Initializing session parameters (Cmd 100, Sub 0)...")
        ack_cmd, ack_status = send_control_packet(sock, CMD_SETUP, 0, data=[3, 0, 0], expect_resp=True)
        version = (ack_status >> 16) & 0xFFFF
        print(f"  [+] Protocol version: {version} (Status: 0x{ack_status:08X})")

        # Step 3: Negotiate Packet Size (Cmd 100, Sub 5 -> 128 KB)
        print(f"[*] Setting streaming packet size to {CHUNK_SIZE // 1024} KB...")
        send_control_packet(sock, CMD_SETUP, 5, data=[CHUNK_SIZE], expect_resp=True)

        # Step 4: Begin Session (Cmd 100, Sub 2 with 64-bit total payload size)
        print(f"[*] Starting download session (Cmd 100, Sub 2: {total_payload} bytes / {total_payload / 1024 / 1024:.2f} MB)...")
        total_low = total_payload & 0xFFFFFFFF
        total_high = (total_payload >> 32) & 0xFFFFFFFF
        send_control_packet(sock, CMD_SETUP, 2, data=[total_low, total_high], expect_resp=True)

        # Step 5: Read PIT table from device
        print("[*] Requesting partition table (PIT) from device...")
        ack_cmd, pit_size = send_control_packet(sock, CMD_PIT, 1, expect_resp=True)
        pit_map = None  # Never fall back to guessed partition IDs for writes
        if ack_cmd == CMD_PIT and 0 < pit_size < 100000:
            print(f"  [+] Device PIT size: {pit_size} bytes. Downloading...")
            pit_data = bytearray()
            chunk_cnt = (pit_size + 499) // 500
            for i in range(chunk_cnt):
                # Cmd 101, Sub 2 (expect_resp=False, device streams raw 500 bytes)
                send_control_packet(sock, CMD_PIT, 2, data=[i], expect_resp=False)
                rem = min(500, pit_size - len(pit_data))
                chunk = recv_exact(sock, rem)
                pit_data.extend(chunk)
            # Finalize PIT transfer
            send_control_packet(sock, CMD_PIT, 3, expect_resp=True)
            pit_map = r800_safety.parse_pit_strict(bytes(pit_data))
            r800_safety.validate_r800_pit(pit_map)
            # Complete geometry audit before any CMD_FILE_TRANSFER (102).
            geometry = r800_geometry.parse_pit_geometry(bytes(pit_data))
            transfer_plan = r800_geometry.plan_image_transfers(geometry, members)
            print(f"  [+] Live PIT validated ({len(pit_map)} flash-file mappings).")
            print("  [+] Assumed 512-byte sector geometry / 128-KiB padded-transfer check:")
            for item in transfer_plan:
                print(f"      {item['image']}: {item['image_bytes']} bytes "
                      f"(padded {item['transmitted_padded_bytes']}) / "
                      f"capacity {item['assumed_partition_bytes']} bytes")
        else:
            raise r800_safety.SafetyError("No valid live PIT; refusing all writes.")

        # Step 6: Stream each partition file in the AP archive
        print("\n" + "=" * 72)
        print("  STREAMING PARTITIONS TO FLASH MEMORY")
        print("=" * 72)

        for f_idx, member in enumerate(members):
            filename = member.name
            file_size = member.size
            part_id = pit_map[filename]  # Live, fully validated PIT only

            print(f"\n[*] [{f_idx + 1}/{len(members)}] Preparing: {filename} (ID: {part_id}, Size: {file_size / 1024 / 1024:.2f} MB)")

            stream = tar_obj.extractfile(member)
            file_bytes_sent = 0
            t_start = time.time()

            while file_bytes_sent < file_size:
                window_bytes_to_send = min(WINDOW_SIZE, file_size - file_bytes_sent)
                aligned_window_size = ((window_bytes_to_send + CHUNK_SIZE - 1) // CHUNK_SIZE) * CHUNK_SIZE

                # Cmd 102, Sub 0: RQT_XMIT_DATA_START (resets chunk seq counter)
                _, ack_status = send_control_packet(sock, CMD_FILE_TRANSFER, 0, expect_resp=True)
                require_transfer_success(ack_status, "window start")

                # Cmd 102, Sub 2: Announce aligned window size to device
                _, ack_status = send_control_packet(
                    sock, CMD_FILE_TRANSFER, 2, data=[aligned_window_size], expect_resp=True)
                require_transfer_success(ack_status, "window size negotiation")

                window_sent = 0
                while window_sent < window_bytes_to_send:
                    to_read = min(CHUNK_SIZE, window_bytes_to_send - window_sent)
                    chunk = read_image_chunk(stream, to_read, filename)
                    actual_len = len(chunk)

                    # NetOdin always transmits full CHUNK_SIZE (128 KB) blocks, zero-padding the last block
                    if len(chunk) < CHUNK_SIZE:
                        chunk = chunk + b"\x00" * (CHUNK_SIZE - len(chunk))

                    sock.sendall(chunk)

                    # Each chunk is acknowledged with an 8-byte status packet: <seq:status>, e.g. <0:0>
                    ack = recv_exact(sock, 8)
                    ack_seq, ack_status = struct.unpack("<II", ack)
                    require_transfer_success(
                        ack_status,
                        f"data chunk at offset {file_bytes_sent + window_sent} (ACK seq {ack_seq})")

                    window_sent += actual_len
                    format_progress(filename, file_bytes_sent + window_sent, file_size, t_start)

                file_bytes_sent += window_sent
                is_file_complete = 1 if file_bytes_sent >= file_size else 0

                # Cmd 102, Sub 3: Commit window to eMMC
                # Data payload matching NetOdin3.exe & wireless_download.elf:
                # [0, window_bytes_to_send, 0, 0, part_id, is_file_complete, 0, 0]
                cmd_data = [0, window_bytes_to_send, 0, 0, part_id, is_file_complete, 0, 0]
                ack_cmd, ack_status = send_control_packet(sock, CMD_FILE_TRANSFER, 3, data=cmd_data, expect_resp=True)
                require_transfer_success(ack_status, f"eMMC commit for {filename}")

            sys.stdout.write("\n")
            print(f"  [+] {filename}: write acknowledged by device (NO read-back verification).")

        # Step 7: Close Session & Reboot
        print("\n" + "=" * 72)
        print("[*] All partitions flashed successfully!")
        print("[*] Closing download session (Cmd 103, Sub 0)...")
        send_control_packet(sock, CMD_SESSION_END, 0, expect_resp=True)

        if auto_reboot:
            print("[*] Issuing device reboot command (Cmd 103, Sub 1)...")
            send_control_packet(sock, CMD_SESSION_END, 1, expect_resp=True)
            print("[+] PASS! Galaxy Watch is now rebooting.")
        else:
            print("[*] Auto-reboot skipped.")

        print("=" * 72)

    finally:
        sock.close()
        srv.close()
        tar_obj.close()


def reboot_only(host: str = "0.0.0.0", port: int = ODIN_PORT):
    """Handshake with a watch in Download (Wireless) mode and reboot it to the
    normal OS without writing anything. Used to leave a boot-to-recovery loop
    with a warm reset (keeps DRAM, so the previous kernel's log ring survives)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)
    print(f"[*] REBOOT-ONLY: listening on {host}:{port}; nothing will be flashed.")
    print("[*] Put the watch in 'Download (Wireless)' AP mode and join its Wi-Fi...")
    sock, client_addr = srv.accept()
    print(f"[+] Watch connected from {client_addr[0]}:{client_addr[1]}")
    sock.settimeout(60.0)
    try:
        sock.sendall(b"ODIN")
        resp = recv_exact(sock, 4)
        if resp != b"LOKE":
            raise ValueError(f"Handshake failed! Expected 'LOKE', got {resp!r}")
        print("[+] Handshake OK ('LOKE')")
        ack_cmd, ack_status = send_control_packet(sock, CMD_SETUP, 0, data=[3, 0, 0], expect_resp=True)
        print(f"[+] Protocol version {(ack_status >> 16) & 0xFFFF}")
        print("[*] Closing session (Cmd 103, Sub 0)...")
        send_control_packet(sock, CMD_SESSION_END, 0, expect_resp=True)
        print("[*] Rebooting (Cmd 103, Sub 1)...")
        send_control_packet(sock, CMD_SESSION_END, 1, expect_resp=True)
        print("[+] Reboot command accepted. Nothing was written.")
    finally:
        sock.close()
        srv.close()


def main():
    parser = argparse.ArgumentParser(description="NetOdin Python Flasher for Samsung Galaxy Watch / Tizen")
    parser.add_argument("--reboot-only", action="store_true", help="Only handshake and reboot the watch; flash nothing")
    parser.add_argument("--preflight-only", action="store_true", help="Validate local archive; no network or writes")
    parser.add_argument("--confirm-r800", action="store_true", help="Explicitly accept risky SM-R800 live flashing")
    parser.add_argument("--combination-reference", help="Local, independently obtained R800 combination .tar.md5; required before live flashing")
    parser.add_argument("--ap", required=False, help="Path to firmware package (.tar or .tar.md5)")
    parser.add_argument("--port", type=int, default=ODIN_PORT, help=f"TCP port to listen on (default: {ODIN_PORT})")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind (default: 0.0.0.0)")
    parser.add_argument("--no-reboot", action="store_true", help="Do not reboot watch after flashing")
    args = parser.parse_args()

    if args.reboot_only:
        reboot_only(host=args.host, port=args.port)
        return
    if not args.ap:
        parser.error("--ap is required unless --reboot-only is given")
    if args.preflight_only:
        if args.combination_reference:
            r800_recovery_audit.audit_release(args.ap, args.combination_reference)
            print("[PASS] Offline package+reference comparison. Device compatibility NOT proven.")
        else:
            r800_safety.preflight_file(args.ap)
            print("[PASS] Offline package checks only. Bootloader/recovery NOT verified.")
        return
    if not args.confirm_r800:
        parser.error("Live flashing requires --confirm-r800 after offline preflight. "
                     "Bootloader compatibility and physical recovery remain unverified.")
    if not args.combination_reference:
        parser.error("Live flashing also requires --combination-reference. "
                     "Package-only validation does not protect recovery partitions.")
    flash_ap_package(
        args.ap, host=args.host, port=args.port, auto_reboot=not args.no_reboot,
        combination_path=args.combination_reference)


if __name__ == "__main__":
    main()
