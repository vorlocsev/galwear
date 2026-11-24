#!/bin/sh
# Build/link experimental Android HALs in scratch, emit JSON only.
set -eu
[ "$#" -eq 4 ] || exit 2
repo=$(cd "$1" && pwd)
ndk=$(cd "$2" && pwd)
tiny=$(cd "$3" && pwd)
out=$4
[ ! -e "$out" ] || exit 2
mkdir -p "$out"
out=$(cd "$out" && pwd)
sh "$repo/build/r800_hal_compile_smoke.sh" "$repo" "$ndk" "$tiny" "$out/objects"
# The external checkout is a disposable CI dependency. Do not alter its source.
git -C "$tiny" archive HEAD | tar -xf - -C "$out"
patch="$repo/build/patches/tinyalsa-2.0.0-sync-ptr.patch"
(cd "$out" && git apply --check "$patch" && git apply "$patch")
bin="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
cc="$bin/armv7a-linux-androideabi28-clang"
for module in pcm pcm_hw mixer mixer_hw limits; do
    "$cc" -std=gnu11 -O2 -fPIC -I"$out/include" \
        -c "$out/src/$module.c" -o "$out/$module.o"
done
"$bin/llvm-ar" rcs "$out/libtinyalsa.a" "$out/pcm.o" "$out/pcm_hw.o" "$out/mixer.o" "$out/mixer_hw.o" "$out/limits.o"
for entry in 'audio_r800 audio.primary.r800.so' 'gps_r800 gps.r800.so' 'sensors_r800 sensors.r800.so' 'hwcomposer_r800 hwcomposer.r800.so'; do
    set -- $entry
    module=$1
    name=$2
    if [ "$module" = audio_r800 ]; then
        set -- "$out/libtinyalsa.a"
    else
        set --
    fi
    "$cc" -shared -Wl,--no-undefined -Wl,--exclude-libs,ALL -Wl,-soname,"$name" \
        "$out/objects/$module.o" "$@" -llog -ldl -lm -o "$out/$name"
done
python3 "$repo/build/r800_hal_link_audit.py" --directory "$out" --compile-report "$out/objects/hal-compile.json" \
    --patch "$patch" --readelf "$bin/llvm-readelf" --output "$out/hal-link.json"
