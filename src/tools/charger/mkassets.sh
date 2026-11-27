#!/bin/sh
# Prepare local non-release display assets; no donor files are published.
# Usage: mkassets.sh <param.bin> <bootanimation.zip> <new-output-dir> <font-file>
set -eu
[ "$#" -eq 4 ] || { echo "usage: $0 <param.bin> <bootanimation.zip> <new output> <font file>" >&2; exit 2; }
P=$1; Z=$2; O=$3; FONT=$4
M=$(command -v magick || command -v convert)
[ -f "$FONT" ] && [ ! -e "$O" ] && [ ! -L "$O" ]
PARENT=$(CDPATH= cd -- "$(dirname -- "$O")" && pwd)
O=$PARENT/$(basename -- "$O")
T=$(mktemp -d "$PARENT/.r800-assets.XXXXXX")
trap 'rm -rf -- "$T"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$T/out" "$T/out/charger"
# Never extract archive paths. Read only unique bounded regular entries.
python3 - "$P" "$Z" "$T" <<'PY'
import pathlib, sys, tarfile, zipfile, stat
p, z, root = map(pathlib.Path, sys.argv[1:])
for source, maximum in ((p, 64*1024**2), (z, 128*1024**2)):
    st = source.lstat()
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= maximum:
        raise ValueError("Expected bounded regular asset archive")
with tarfile.open(p, "r:*") as archive:
    members = []
    for member in archive:
        if len(members) >= 1024:
            raise ValueError("Too many param members")
        members.append(member)
    for i in range(10):
        name = "pow_digital_num_%d.raw" % i
        matches = [m for m in members if m.name == name]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size != 55 * 110 * 3:
            raise ValueError("Invalid charger digit: " + name)
        raw = archive.extractfile(matches[0]).read()
        if len(raw) != 55 * 110 * 3:
            raise ValueError("Truncated charger digit")
        (root / "out" / "charger" / ("d%d.rgb" % i)).write_bytes(raw)
with zipfile.ZipFile(z) as archive:
    if len(archive.infolist()) > 8192:
        raise ValueError("Too many bootanimation members")
    matches = [i for i in archive.infolist() if i.filename == "part1/00000.png"]
    if len(matches) != 1 or not 24 <= matches[0].file_size <= 8 * 1024 * 1024:
        raise ValueError("Invalid bootanimation frame")
    mode = matches[0].external_attr >> 16
    if matches[0].is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
        raise ValueError("Expected regular PNG member")
    raw = archive.read(matches[0])
    if raw[:8] != b"\x89PNG\r\n\x1a\n" or raw[12:16] != b"IHDR":
        raise ValueError("Not PNG")
    import struct
    w, h = struct.unpack(">II", raw[16:24])
    if not 1 <= w <= 2048 or not 1 <= h <= 2048:
        raise ValueError("PNG geometry exceeds budget")
    (root / "frame.png").write_bytes(raw)
PY
"$M" -limit memory 128MiB -limit map 256MiB -limit disk 256MiB "$T/frame.png" -background black -gravity center -extent 360x360 -alpha remove -alpha opaque -depth 8 BGRA:"$T/out/splash.raw"
"$M" -background black -fill white -font "$FONT" -pointsize 44 label:% -trim +repage \
    -gravity south -background black -extent 36x96 -gravity north -extent 36x110 -depth 8 rgb:"$T/out/charger/pct.rgb"
"$M" -size 320x240 xc:black -fill white -stroke none \
    -draw "polygon 194,18 104,130 152,130 128,222 216,106 166,106 194,18" -resize 80x60 -depth 8 rgb:"$T/out/charger/bolt.rgb"
python3 - "$T/out" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
sizes = {"splash.raw": 360*360*4, "charger/pct.rgb": 36*110*3,
         "charger/bolt.rgb": 80*60*3}
sizes.update({"charger/d%d.rgb" % i: 55*110*3 for i in range(10)})
report = {}
for name, size in sizes.items():
    data = (root / name).read_bytes()
    if len(data) != size:
        raise ValueError("Unexpected raw asset size: " + name)
    report[name] = {"bytes": size, "sha256": hashlib.sha256(data).hexdigest()}
(root / "assets-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True))
print("PASS: 13 display assets; device rendering NOT tested")
PY
mkdir -- "$O"
# mkdir is the no-overwrite gate; the directory is new and must be private.
if ! mv -- "$T/out/"* "$O/"; then
    echo "Asset publication incomplete; discard the new output directory" >&2
    exit 2
fi
echo "NON-RELEASE assets prepared at $O"
