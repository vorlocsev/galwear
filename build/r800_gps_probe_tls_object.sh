#!/bin/sh
# Check the ARM32 probe object, not the runtime ABI. Accept GNU or LLVM readelf.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 readelf probe.o" >&2; exit 2; }
export LC_ALL=C
READELF=$1
OBJECT=$2
SYMBOLS=$("$READELF" -W -s "$OBJECT")
RELOCS=$("$READELF" -W -r "$OBJECT")
# Require the actual TLS variable and local-exec relocations. No compiler
# runtime shims, emulated TLS or unresolved helper are admitted.
printf '%s\n' "$SYMBOLS" | awk '$4 == "TLS" && $5 == "LOCAL" && $8 == "tls" && $3 == 4 { found++ } END { exit (found != 1) }'
printf '%s\n' "$RELOCS" | grep -Eq 'R_ARM_TLS_LE32[[:space:]]+.*[[:space:]]tls([[:space:]]|$)'
EXPECTED=$(printf '%s\n' __libc_start_main dlclose dlopen dlsym fflush gnu_get_libc_version pthread_create pthread_join puts strcmp | sort)
ACTUAL=$(printf '%s\n' "$SYMBOLS" | awk '$7 == "UND" && NF >= 8 { print $8 }' | sort -u)
if [ "$ACTUAL" != "$EXPECTED" ]; then
    printf '%s\n' "Unexpected ARM32 probe imports:" "$ACTUAL" >&2
    exit 2
fi
echo "ARM32_TLS_OBJECT_CONTRACT=PASS"
echo "TLS_RUNTIME_VERIFIED=false"
