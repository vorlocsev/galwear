# Live exact-head CI metadata in GNSS readiness

Baseline a75251157b0c743247425e3d40adc4db5eda76b3: all seven
workflows completed successfully; GNSS run 45771987627 confirmed
the sixteen readiness tests. GitHub job metadata verified for
host 139746572628, NDK 139746572556 and QEMU 139746572342.

Use an authenticated gh CLI and clean checkout:
    python3 build/r800_gnss_readiness.py --check-ci

Queries live metadata from the fork only, exact source SHA.
Requires seven named workflow paths, newest run ID per workflow,
successful attempt-specific GNSS jobs and required steps.
Rejects incomplete pagination, foreign head/repository,
wrong attempts, skipped steps and changed selection.
No workflows dispatched, no artifacts downloaded.
ci_verified denotes metadata only; ci_logs_verified remains false.
No runtime gates are promoted. Thirteen synthetic metadata tests
pending CI. Original Tizen and physical GNSS not verified.
safe_to_flash=false.
