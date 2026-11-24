"""Conservative SM-R800 PIT geometry and image-size gate.

The PIT block_count is interpreted as 512-byte sectors, matching the eMMC
partition-size convention used in the project's R800 build. This assumption
MUST be checked against an authentic live PIT before any real flashing.
Passing this gate does NOT authenticate a bootloader or prove physical safety.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Iterable

from r800_safety import (
    EXPECTED_IMAGES, PIT_HEADER_SIZE, PIT_ENTRY_SIZE, SafetyError,
    parse_pit_strict, validate_r800_pit,
)

SECTOR_BYTES = 512
TRANSFER_BLOCK_BYTES = 131072


@dataclass(frozen=True)
class PartitionGeometry:
    flash_name: str
    partition_name: str
    identifier: int
    device_type: int
    offset_blocks: int
    block_count: int

    @property
    def capacity_bytes(self) -> int:
        return self.block_count * SECTOR_BYTES


def parse_pit_geometry(pit: bytes) -> dict[str, PartitionGeometry]:
    """Require authentic structural PIT parsing; never infer missing geometry."""
    mapping = parse_pit_strict(pit)
    validate_r800_pit(mapping)
    count = struct.unpack_from("<I", pit, 4)[0]
    out: dict[str, PartitionGeometry] = {}
    for index in range(count):
        entry = pit[PIT_HEADER_SIZE + index * PIT_ENTRY_SIZE:
                    PIT_HEADER_SIZE + (index + 1) * PIT_ENTRY_SIZE]
        name_bytes = entry[68:100].split(b"\0", 1)[0]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SafetyError("Invalid PIT flash filename encoding") from exc
        if name not in EXPECTED_IMAGES:
            continue
        part_bytes = entry[36:68].split(b"\0", 1)[0]
        try:
            partition_name = part_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SafetyError(f"Invalid PIT partition name encoding for {name}") from exc
        identifier = struct.unpack_from("<I", entry, 8)[0]
        device_type = struct.unpack_from("<I", entry, 4)[0]
        block_offset, block_count = struct.unpack_from("<II", entry, 20)
        if block_count == 0:
            raise SafetyError(f"Missing/zero PIT block count for {name}")
        if device_type > 3:
            raise SafetyError(f"Unknown PIT device type {device_type} for {name}")
        # This is a conservative consistency check, not evidence that offsets
        # address the same physical bank for every partition.
        if block_offset + block_count > 0x100000000:
            raise SafetyError(f"PIT block range overflow for {name}")
        if identifier != EXPECTED_IMAGES[name]:
            raise SafetyError(f"Wrong partition identifier for {name}")
        out[name] = PartitionGeometry(
            flash_name=name, partition_name=partition_name,
            identifier=identifier, device_type=device_type,
            offset_blocks=block_offset, block_count=block_count,
        )
    missing = set(EXPECTED_IMAGES) - out.keys()
    if missing:
        raise SafetyError("PIT geometry unavailable for: " + ", ".join(sorted(missing)))
    return out


def plan_image_transfers(
    geometry: dict[str, PartitionGeometry],
    members: Iterable,
) -> list[dict[str, int | str]]:
    """Validate ALL images before first CMD_FILE_TRANSFER.

    A transport block is padded to 128 KiB. Check the padded transfer size
    conservatively, not just the logical TAR member length.
    """
    plan: list[dict[str, int | str]] = []
    seen: set[str] = set()
    for member in members:
        name = member.name
        if name not in EXPECTED_IMAGES or name in seen:
            raise SafetyError(f"Unexpected or duplicate firmware image: {name}")
        seen.add(name)
        item = geometry.get(name)
        if item is None:
            raise SafetyError(f"Missing PIT geometry for {name}")
        logical_size = member.size
        if logical_size <= 0:
            raise SafetyError(f"Empty image {name}")
        padded_size = (
            (logical_size + TRANSFER_BLOCK_BYTES - 1) // TRANSFER_BLOCK_BYTES
        ) * TRANSFER_BLOCK_BYTES
        if padded_size > item.capacity_bytes:
            raise SafetyError(
                f"{name} exceeds assumed PIT partition capacity: "
                f"image={logical_size}, padded={padded_size}, "
                f"capacity={item.capacity_bytes} bytes "
                f"({item.block_count} x {SECTOR_BYTES})")
        plan.append({
            "image": name,
            "partition_id": item.identifier,
            "image_bytes": logical_size,
            "transmitted_padded_bytes": padded_size,
            "assumed_partition_bytes": item.capacity_bytes,
        })
    if seen != set(EXPECTED_IMAGES):
        raise SafetyError("Cannot validate transfer plan: missing archive members")
    return plan
