#!/usr/bin/env python3
"""Compare measured NDK ARM32 fields against pinned compat source contract."""
import hashlib
import json
from pathlib import Path
import re
import sys

BASE = "50db73fc799f20a7120a8b5f653b16cc123d856f"
BLOBS = ("946ab080ac00315f6dc818bd4842970820b71029",
         "ed0a120d4f084fa0cfc10b5257ea9bce0c3d3a24")

# Source-derived, not compiled kernel measurements: packed compat status
# has 3 32-bit fields, 2 32-bit timespecs and suspended_state.
# sync_ptr32 has a 4-byte flag and two 64-byte unions; xferi32 3 words.
def ioctl(direction, number, size):
    return direction << 30 | size << 16 | ord("A") << 8 | number


EXPECTED = {
    "pointer_bytes": 4, "uframes_bytes": 4,
    "sync_ptr_bytes": 132, "mmap_status_bytes": 32, "mmap_control_bytes": 8,
    "sync_flags_offset": 0, "sync_status_offset": 4, "sync_control_offset": 68,
    "status_hw_ptr_offset": 8, "control_appl_ptr_offset": 0,
    "control_avail_min_offset": 4, "xferi_bytes": 12,
    "xferi_result_offset": 0, "xferi_buf_offset": 4, "xferi_frames_offset": 8,
    "ioctl_sync_ptr": ioctl(3, 0x23, 132),
    "ioctl_readi": ioctl(2, 0x51, 12),
    "ioctl_writei": ioctl(1, 0x50, 12),
    "flag_hwsync": 1, "flag_appl": 2, "flag_avail_min": 4,
}


def blob_sha(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def compare(measured):
    return {k: {"expected": v, "measured": measured.get(k)}
            for k, v in EXPECTED.items()
            if type(measured.get(k)) is not int or measured[k] != v}


def verify_source(compat, uapi):
    if (blob_sha(compat), blob_sha(uapi)) != BLOBS:
        raise ValueError("pinned kernel source blob hash mismatch")
    c = re.sub(r"\s+", "", compat.decode())
    h = re.sub(r"\s+", "", uapi.decode())
    markers = (
        "structsnd_xferi32{s32result;u32buf;u32frames;};",
        "structsnd_pcm_mmap_status32{s32state;s32pad1;u32hw_ptr;structcompat_timespectstamp;s32suspended_state;structcompat_timespecaudio_tstamp;}__attribute__((packed));",
        "structsnd_pcm_mmap_control32{u32appl_ptr;u32avail_min;};",
        "structsnd_pcm_sync_ptr32{u32flags;union{structsnd_pcm_mmap_status32status;unsignedcharreserved[64];}s;union{structsnd_pcm_mmap_control32control;unsignedcharreserved[64];}c;}__attribute__((packed));",
        "SNDRV_PCM_IOCTL_SYNC_PTR32=_IOWR('A',0x23,structsnd_pcm_sync_ptr32)",
        "SNDRV_PCM_IOCTL_WRITEI_FRAMES32=_IOW('A',0x50,structsnd_xferi32)",
        "SNDRV_PCM_IOCTL_READI_FRAMES32=_IOR('A',0x51,structsnd_xferi32)",
        "if(!(sflags&SNDRV_PCM_SYNC_PTR_APPL))control->appl_ptr=scontrol.appl_ptr;elsescontrol.appl_ptr=control->appl_ptr%boundary;",
        "if(!(sflags&SNDRV_PCM_SYNC_PTR_AVAIL_MIN))control->avail_min=scontrol.avail_min;elsescontrol.avail_min=control->avail_min;",
        "caseSNDRV_PCM_IOCTL_SYNC_PTR32:returnsnd_pcm_ioctl_sync_ptr_compat(substream,argp);",
    )
    if not all(m in c for m in markers):
        raise ValueError("expected compat source contract missing")
    for name, bit in (("HWSYNC", 0), ("APPL", 1), ("AVAIL_MIN", 2)):
        if "#defineSNDRV_PCM_SYNC_PTR_" + name + "(1<<" + str(bit) + ")" not in h:
            raise ValueError("flag definition mismatch: " + name)


def main():
    if len(sys.argv) != 5:
        raise SystemExit("usage: audit <hal-json> <pcm_compat.c> <asound.h> <output>")
    hal, compat, uapi, output = map(Path, sys.argv[1:])
    evidence = json.loads(hal.read_text())
    verify_source(compat.read_bytes(), uapi.read_bytes())
    measured = evidence["audio_candidate"]["pcm_ndk_abi"]
    mismatches = compare(measured)
    report = {
        "schema": "galwear-r800-pcm-compat-v1",
        "commit": evidence["commit"],
        "kernel_base": BASE,
        "source_blob_sha1": dict(zip(("pcm_compat.c", "asound.h"), BLOBS)),
        "status": "SOURCE_LAYOUT_MATCH" if not mismatches else "SOURCE_LAYOUT_MISMATCH",
        "expected_source_layout": EXPECTED,
        "measured_ndk_layout": measured,
        "mismatches": mismatches,
        "sync_ptr_readback_semantics_confirmed_in_source": True,
        "kernel_compiled_layout_verified": False,
        "kernel_runtime_compat_verified": False,
        "hardware_tested": False,
        "safe_to_flash": False,
    }
    output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"], json.dumps(mismatches))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
