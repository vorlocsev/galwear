#!/bin/sh
# Compatibility entrypoint; use the curated non-release builder.
# No deletion of home directories and no implicit legacy donor root.
set -eu
[ "$#" -eq 3 ] || {
    echo "usage: $0 <curated-input-tree> <release-tree> <new-output.tar>" >&2
    exit 2
}
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sh "$BASE/mkpayload-release.sh" "$@"
