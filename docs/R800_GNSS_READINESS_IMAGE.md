# GNSS readiness: raw Tizen image gate

Baseline 2df4af44a4e7c0cd313f28283dd5117a9dcb6c8f passed 7/7
workflows. GPS run 45771352212 host job 139744478003 confirmed
all six ext4 GNSS image audit tests and the full offline gate.

New optional paired inputs to the existing readiness report:
    python3 build/r800_gnss_readiness.py \
      --tizen-image /path/rootfs.img --tizen-image-sha256 EXPECTED_SHA256

This invokes only the static image auditor. Its schema, expected
image digest, verified snapshot and explicit false runtime/ABI
claims are checked before reporting STATIC_PASS. The expanded
report retains full evidence and digest. Missing inputs remain
NOT_TESTED. The prepared-tree preflight and IPC path checks remain
independent, even if image closure passes. There is no automatic
donor execution or runtime promotion. Seven additional report tests
are pending CI. Original Tizen image remains unavailable.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
