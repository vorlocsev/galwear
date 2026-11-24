# SM-R800 recovery audit (offline)

This branch builds on `hardening/r800-installer-preflight-20261124`, but it is **fork-only**. It does not open a pull request, write to upstream, modify `main`, or contact a watch.

## Run

With the released `R800-WearOS.tar.md5` and a separately obtained Samsung `COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5`:

```shell
python3 installer/r800_recovery_audit.py \
  --package R800-WearOS.tar.md5 \
  --combination COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5 \
  --report r800-recovery-audit.json
```

This command only reads the two archives and optionally writes a local JSON report. The reference combination firmware can contain `cm.bin`, but the final Wear OS package MUST NOT contain it. The check reads eight files that `build/mkrelease.sh` is supposed to copy unchanged:

- `sboot.bin`, `param.bin`
- `dzImage-recovery`, `ramdisk-recovery.img`, `ramdisk.img`
- `system-data.img`, `nad_refer.bin`, `nad_fw.bin`

Each file is compared by SHA-256. Both NZIT boot containers are structurally validated, including EXYN device-tree table bounds. The Wear OS firmware archive must pass its independent MD5/member-allowlist preflight.

## Important limits

- SHA-256 equality only proves that a file matches the **provided** reference; an untrusted or mislabeled combination archive is NOT an authenticated Samsung source.
- The NZIT RSA trailer's presence and bounds are inspected, **not its signature**.
- No real Wear OS 2.3 GiB release archive was provided for validation, and no watch or real PIT was available.
- These tests **do not prove safe retail-S-Boot installation, USB recovery or suspend/resume stability**.
- The included tests use small synthetic TAR/NZIT files. Keep the flash operation disabled pending independent hardware review.
