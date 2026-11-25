# R800 GNSS readiness report (non-release)

From a clean checkout:

```sh
python3 build/r800_gnss_readiness.py --run-offline
```

Add --android-root, --tizen-root, --binary and --libdir as local inputs become
available. Missing inputs remain NOT_TESTED. The wrapper actually runs the
requested local tests and static scripts, records return codes, report/log
digests, and the exact clean checkout SHA. No donor binary execution, no
network, no CI dispatch, no flash. It does not trust imported JSON or pasted
PASS markers. The static tool reports are embedded; their hashes are evidence
of bytes, not proof of donor authenticity. Run on immutable offline inputs.

STATIC_PASS means static evidence only. QEMU, effective UID/GID, HIDL,
SELinux access, Broadcom transport and physical location remain separate
runtime gates; CI is never inferred from a local run. A zero exit code
means no attempted check failed, NOT release or daemon approval.
HOLD_RUNTIME_UNVERIFIED and safe_to_flash=false remain mandatory.

Use stdout for the report; redirect outside the checkout so the clean-tree
check is not affected. The wrapper is not a CI result importer.
