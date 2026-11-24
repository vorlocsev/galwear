#!/usr/bin/env python3
"""Compile the pinned kernel's extracted DECON data layout on both Android ABIs."""
import argparse
from pathlib import Path
import re
import subprocess

STRUCTS = ("decon_win_rect", "dpp_params", "decon_frame",
           "decon_win_config", "decon_win_config_data")
MAPPING = {"decon_win_rect": "r800_win_rect", "dpp_params": "r800_dpp_params",
           "decon_frame": "r800_frame", "decon_win_config": "r800_win_config",
           "decon_win_config_data": "r800_win_config_data"}


def extract(text, name):
    match = re.search(r"\bstruct\s+" + name + r"\s*\{", text)
    if not match:
        raise ValueError("Missing kernel declaration " + name)
    depth = 1
    i = match.end()
    while i < len(text) and depth:
        depth += (text[i] == "{") - (text[i] == "}")
        i += 1
    if depth or text[i:i+1] != ";":
        raise ValueError("Incomplete kernel declaration " + name)
    return text[match.start():i+1]


def generate(kernel, mirror):
    # Only these specific declarations are extracted; no arbitrary kernel
    # headers are compiled. Kernel enums are represented by 32-bit int,
    # as in the existing userspace mirror; verify their values separately.
    kernel = re.sub(r"/\*.*?\*/|//[^\n]*", "", kernel, flags=re.S)
    for name, expected in (("MAX_DECON_WIN", 3), ("MAX_PLANE_CNT", 3)):
        if not re.search(r"^#define\s+" + name + r"\s+" + str(expected) + r"\s*$", kernel, re.M):
            raise ValueError("Unexpected " + name)
    if not re.search(r"#define\s+S3CFB_WIN_CONFIG\s+_IOW\('F',\s*209,\s*\\\s*struct decon_win_config_data\)", kernel):
        raise ValueError("Unexpected kernel ioctl definition")
    declarations = "\n".join(extract(kernel, n) for n in STRUCTS)
    declarations = re.sub(r"\benum\s+(?:dpp_rotate|dpp_csc_eq|dpp_comp_src|dpp_hdr_standard|decon_blending|decon_pixel_format)\b", "int", declarations)
    assertions = "\n".join(x for x in mirror.splitlines() if x.startswith("_Static_assert("))
    if len(assertions.splitlines()) < 16:
        raise ValueError("Missing layout assertions")
    for source, target in sorted(MAPPING.items(), key=lambda x: -len(x[1])):
        assertions = re.sub(r"\b" + target + r"\b", source, assertions)
    assertions = assertions.replace("R800_S3CFB_WIN_CONFIG", "S3CFB_WIN_CONFIG")
    return ("#include <stddef.h>\n#include <stdint.h>\n#include <stdbool.h>\n#include <sys/ioctl.h>\n"
            "typedef uint64_t dma_addr_t;\ntypedef uint32_t u32;\ntypedef uint32_t __u32;\n"
            "#define MAX_DECON_WIN 3\n#define MAX_PLANE_CNT 3\n"
            + declarations + "\n#define S3CFB_WIN_CONFIG _IOW('F', 209, struct decon_win_config_data)\n"
            + assertions + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel-header", type=Path, required=True)
    p.add_argument("--mirror", type=Path, required=True)
    p.add_argument("--ndk", type=Path, required=True)
    p.add_argument("--scratch", type=Path, required=True)
    a = p.parse_args()
    a.scratch.mkdir(parents=True, exist_ok=False)
    source = a.scratch / "kernel-layout.c"
    source.write_text(generate(a.kernel_header.read_text(), a.mirror.read_text()))
    mirror = a.scratch / "hal-layout.c"
    mirror.write_text('#include "r800_decon_abi.h"\n')
    bindir = a.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    for target in ("armv7a-linux-androideabi28-clang", "aarch64-linux-android28-clang"):
        for unit in (source, mirror):
            subprocess.run([str(bindir / target), "-std=gnu11", "-fsyntax-only",
                            "-I" + str(a.mirror.resolve().parent), str(unit)], check=True, timeout=30)
    print("DECON layout compile assertions passed on both ABIs; runtime unverified")


if __name__ == "__main__":
    main()
