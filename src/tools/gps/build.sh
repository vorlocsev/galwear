#!/bin/sh
# Tizen ARM32 soft-float GPS bridge, build only, never run on host.
# Usage: build.sh <NDK r27c> <local Tizen library directory> <new-output-file>
set -eu
XTRA_ABI=${R800_XTRA_ABI:-0}
case "$XTRA_ABI" in 0|1|2) ;; *) echo "invalid R800_XTRA_ABI" >&2; exit 2;; esac
[ "$#" -eq 3 ] || { echo "usage: $0 <NDK r27c> <Tizen lib dir> <new output file>" >&2; exit 2; }
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$S/../../.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
SR=$(CDPATH= cd -- "$2" && pwd -P)
OUT=$3
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output already exists" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
PARENT=$(CDPATH= cd -- "$(dirname -- "$OUT")" && pwd)
OUT=$PARENT/$(basename -- "$OUT")
TMP=$(mktemp -d "$PARENT/.gpsbridge.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -m 700 "$TMP/libs"
SNAPSHOT=$ROOT/build/r800_gps_donor_snapshot.py
python3 "$SNAPSHOT" create "$SR" "$TMP/libs" "$TMP/input.json"
python3 "$SNAPSHOT" verify "$SR" "$TMP/libs" "$TMP/input.json"
# Optional archive-bound NON-RELEASE mode. Verify before invoking compiler.
ARCHIVE=${R800_TIZEN_ARCHIVE:-}
if [ -n "$ARCHIVE" ]; then
    python3 "$ROOT/build/r800_pack_tizen_stage.py" verify --archive "$ARCHIVE" --donor-manifest "$TMP/input.json" > "$TMP/archive.json"
fi
set -- "$TMP/tools/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
    -DR800_XTRA_ABI="$XTRA_ABI" --no-default-config -nostdinc -O2 -fno-pic -no-pie -fno-stack-protector -fno-builtin -ffreestanding -nostdlib -fuse-ld=lld --ld-path="$TMP/tools/ld.lld" \
    -Wl,--hash-style=sysv -Wl,-z,noexecstack -Wl,-z,now -Wl,--no-undefined \
    -Wl,--dynamic-linker=/lib/ld-linux.so.3 -Wl,-e,_start \
    -o "$TMP/gpsbridge" "$TMP/sources/gpsbridge.c" "$TMP/libs/libc.so.6" "$TMP/libs/libdl.so.2" "$TMP/libs/libpthread.so.0"
PROVENANCE=$ROOT/build/r800_gps_provenance.py
python3 "$PROVENANCE" capture "$ROOT" "$NDK" "$TMP/provenance.json" "$@"
python3 "$PROVENANCE" verify "$ROOT" "$NDK" "$TMP/provenance.json" "$@"
# Do not inherit common compiler/loader injection variables.
# The build contract is freestanding and uses only explicit local includes.
(
    unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
    unset COMPILER_PATH GCC_EXEC_PREFIX CCC_OVERRIDE_OPTIONS CLANG_CONFIG_FILE
    unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
    export LC_ALL=C TZ=UTC
    # Donor checks and link use captured NDK executables only.
    for lib in libc.so.6 libdl.so.2 libpthread.so.0 ld-linux.so.3; do
        "$TMP/tools/llvm-readelf" -h "$TMP/libs/$lib" > "$TMP/donor-elf.txt"
        grep -Eq 'Class:[[:space:]]*ELF32[[:space:]]*$' "$TMP/donor-elf.txt"
        grep -Eq 'Data:.*little endian' "$TMP/donor-elf.txt"
        grep -Eq 'Machine:[[:space:]]*ARM[[:space:]]*$' "$TMP/donor-elf.txt"
        grep -Eq 'Type:[[:space:]]*DYN([[:space:]]|$)' "$TMP/donor-elf.txt"
    done
    "$@"
)
python3 "$PROVENANCE" verify "$ROOT" "$NDK" "$TMP/provenance.json" "$@"
(
    unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
    export LC_ALL=C TZ=UTC
    "$TMP/tools/llvm-readelf" -h -l -d --wide "$TMP/gpsbridge" > "$TMP/elf.txt"
)
grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf.txt"
grep -Fq '/lib/ld-linux.so.3' "$TMP/elf.txt"
python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$TMP/gpsbridge" --libdir "$TMP/libs" > "$TMP/audit.json" || {
    cat "$TMP/audit.json" >&2
    exit 2
}
cat "$TMP/audit.json"
python3 "$SNAPSHOT" verify "$SR" "$TMP/libs" "$TMP/input.json"
python3 "$PROVENANCE" verify "$ROOT" "$NDK" "$TMP/provenance.json" "$@"
if [ -n "$ARCHIVE" ]; then
    python3 "$ROOT/build/r800_gps_publish.py" "$TMP/gpsbridge" "$TMP/audit.json" "$TMP/input.json" "$OUT" "$TMP/provenance.json" --archive "$ARCHIVE" --archive-record "$TMP/archive.json"
else
    python3 "$ROOT/build/r800_gps_publish.py" "$TMP/gpsbridge" "$TMP/audit.json" "$TMP/input.json" "$OUT" "$TMP/provenance.json"
fi
echo "R800_XTRA_ABI=$XTRA_ABI (0=disabled; 1=legacy; 2=sized vendor candidate)"
echo "NON-RELEASE Tizen GPS bridge; glibc compatibility and GNSS runtime NOT verified."
