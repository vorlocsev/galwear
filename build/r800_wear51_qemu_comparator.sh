#!/usr/bin/env bash
# Download a signed-repository QEMU comparator, without installing it or changing host binfmt.
set -euo pipefail
root=$(realpath "$1")
test -d "$root"
work="$root/qemu-noble"
mkdir "$work"
mkdir -p "$work/lists/partial" "$work/cache/archives/partial" "$work/download" "$work/extracted"
key=/usr/share/keyrings/ubuntu-archive-keyring.gpg
test -r "$key"
printf 'deb [arch=amd64 signed-by=%s] https://archive.ubuntu.com/ubuntu noble universe\ndeb [arch=amd64 signed-by=%s] https://archive.ubuntu.com/ubuntu noble-updates universe\ndeb [arch=amd64 signed-by=%s] https://security.ubuntu.com/ubuntu noble-security universe\n' "$key" "$key" "$key" > "$work/sources.list"
opts=(-o "Dir::Etc::sourcelist=$work/sources.list" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$work/lists" -o "Dir::Cache=$work/cache" -o Acquire::Retries=3 -o Acquire::Languages=none -o APT::Get::List-Cleanup=0)
apt-get "${opts[@]}" update
version=$(apt-cache "${opts[@]}" policy qemu-user-static | awk '/Candidate:/ {print $2; exit}')
[[ "$version" =~ ^1:8\.2\.2\+ds-0ubuntu1(\.[0-9]+)?$ ]]
(
  cd "$work/download"
  apt-get "${opts[@]}" download "qemu-user-static=$version"
)
mapfile -t packages < <(find "$work/download" -maxdepth 1 -type f -name 'qemu-user-static_*.deb')
test "${#packages[@]}" -eq 1
package="${packages[0]}"
test "$(dpkg-deb -f "$package" Package)" = qemu-user-static
test "$(dpkg-deb -f "$package" Version)" = "$version"
test "$(dpkg-deb -f "$package" Architecture)" = amd64
pin=$(apt-cache "${opts[@]}" show "qemu-user-static=$version" | awk '/^SHA256:/ {print $2; exit}')
[[ "$pin" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$pin" "$package" | sha256sum -c -
dpkg-deb -x "$package" "$work/extracted"
qemu="$work/extracted/usr/bin/qemu-arm-static"
test -f "$qemu" && test ! -L "$qemu" && test -x "$qemu"
readelf -h "$qemu" | grep -q 'Advanced Micro Devices X86-64'
if readelf -W -l "$qemu" | grep -q INTERP; then
  echo 'Comparator has dynamic interpreter' >&2
  exit 1
fi
mkdir "$work/guest"
mkdir "$work/guest/dev" "$work/guest/proc" "$work/guest/tmp"
touch "$work/guest/qemu"
timeout -k 5s 20s bwrap --unshare-all --die-with-parent --new-session --clearenv \
  --ro-bind "$work/guest" / --ro-bind "$qemu" /qemu --dev /dev --proc /proc \
  --tmpfs /tmp --chdir / /qemu --version | tee "$work/version.txt"
grep -q '^qemu-arm version 8\.2\.2' "$work/version.txt"
python3 - "$work" "$package" "$version" "$pin" "$qemu" <<'PY'
import hashlib,json,sys
from pathlib import Path
work,package,version,pin,qemu=sys.argv[1:]
raw=Path(qemu).read_bytes()
result={"repository":"Ubuntu noble signed APT metadata","package_version":version,
        "package_sha256":pin,"qemu_sha256":hashlib.sha256(raw).hexdigest(),
        "qemu_bytes":len(raw),"qemu_version":(Path(work)/"version.txt").read_text().splitlines()[0],
        "host_install_performed":False,"safe_to_flash":False}
(Path(work)/"comparator.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
print("WEAR51_QEMU_COMPARATOR",json.dumps(result,sort_keys=True))
PY
