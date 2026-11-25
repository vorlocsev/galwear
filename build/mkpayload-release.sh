#!/bin/sh
# NON-RELEASE: assemble a curated local payload, not a live watch backup.
# Usage: sh build/mkpayload-release.sh <curated-input-tree> <release-tree> <new-output.tar>
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 <curated-input-tree> <release-tree> <new-output.tar>" >&2; exit 2; }
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$BASE/r800_payload_candidate.py" --source "$1" --release "$2" --output "$3"
