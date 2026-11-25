#!/bin/sh
# Static armv7a builds (they run from start.sh before Android exists; NDK static
# binaries need API >= 29, else bionic aborts on TLS alignment):
#   build.sh <ndk bin dir> <out dir>
set -e
cd "$(dirname "$0")"
"$1/clang" --target=armv7a-linux-androideabi30 -static -O2 -Wall -s -o "$2/r800charger" r800charger.c -lm
"$1/clang" --target=armv7a-linux-androideabi30 -static -O2 -Wall -s -o "$2/wpcd" ../wpcd.c
"$1/clang" --target=armv7a-linux-androideabi30 -static -O2 -Wall -s -o "$2/r800wdui" r800wdui.c
