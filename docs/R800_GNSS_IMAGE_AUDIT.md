# Raw ext4 GNSS closure audit

Baseline 49eb19578cb93dcb358e6f0afeb655c8c973a759 passed all seven
workflows. GPS CI 45771023186 confirmed GNSS preflight 16/16 and
generic Tizen dependencies 21/21.

New command:
    python3 build/r800_gps_image_audit.py --image rootfs.img --sha256 EXPECTED_SHA256

Reads a private hash-verified snapshot via debugfs only. Resolves
bounded guest symlink paths, including fast relative and absolute
links; unsupported link formats require review. Extracts only ELF
dependency candidates into a temporary non-executable tree, checks
the original image and extracted hashes, and reports GNSS symbol,
relocation and Broadcom export evidence. No mount, no execution,
no location cache read. Runtime path metadata is deliberately not
inferred from the extracted subset. Six actual ext4 fixture tests
are pending CI. Original Tizen image unavailable; safe_to_flash=false.
