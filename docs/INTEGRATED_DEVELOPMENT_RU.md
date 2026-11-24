# SM-R800 — integrated hardening (fork-only development)

This branch belongs to **vorlocsev/galwear**. It consolidates the earlier safety-related fork branches and does not modify `main` or publish images, releases, or pull requests. All validation in GitHub Actions uses artificial PIT and TAR/NZIT fixtures. **There is no verified safe first-flash procedure for retail SM-R800.**

## Implemented safeguards

| Area | File(s) | What has been tested |
| --- | --- | --- |
| NetOdin package/PIT gate | `installer/netodin.py`, `installer/r800_safety.py` | Reject missing, corrupt or unexpected PIT and TAR entries; require explicit CLI flashing confirmation |
| Transfer protocol | `installer/netodin.py` | Short image reads stop immediately; nonzero data/commit ACKs cause failure |
| eMMC size bounds | `installer/r800_geometry.py` | Before the first write, reject images too large for the *assumed* capacity of the matching PIT entry |
| Bootloader/recovery comparison | `installer/r800_recovery_audit.py` | Offline SHA-256 comparison against an independently provided combination archive; NZIT and EXYN structural checks |
| Power-management experiment | `payload/android-helper.sh` | Independent flags `SLEEP` and `CPUIDLE_DEEP`; neither experimental deep mode is enabled by default |
| Combined offline report | `installer/r800_preflight_report.py` | Local PIT/archive/optional combination inspection with JSON status and explicit unverified flags |

## Offline commands (safe — they never open a watch connection)

From the repository root, once you have separately obtained the **correct** PIT file and release archive:

```sh
python3 installer/netodin.py --preflight-only --ap R800-WearOS.tar.md5
python3 installer/r800_preflight_report.py \
  --package R800-WearOS.tar.md5 \
  --pit-file SM-R800.pit \
  --output r800-preflight-report.json
```

For a separately supplied, trusted Samsung combination archive, add:

```sh
python3 installer/r800_preflight_report.py \
  --package R800-WearOS.tar.md5 \
  --pit-file SM-R800.pit \
  --combination COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5 \
  --output r800-reference-comparison.json
```

A passing comparison confirms only that local files match the *supplied* reference; it does not certify the provenance of that reference.

## Development checks

```sh
python3 -m compileall -q installer tests
sh -n payload/android-helper.sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

These tests simulate 512-byte-sector PIT geometries, a minimal Odin socket peer, the firmware TAR/MD5 layout, recovery containers and CPU policy paths. The simulator is not an actual Samsung bootloader.

## Explicit blockers

- No authenticated live PIT or retail/engineering S-Boot compatibility evidence is bundled.
- Odin wireless PIT framing and commit semantics have not been confirmed against a real SM-R800 trace.
- The 512-byte PIT sector interpretation is not independently verified on a real watch.
- No reliable wired recovery procedure has been demonstrated as part of this branch.
- Samsung and Google binary firmware images are not included; no full Wear OS build is claimed.
- CPU deep idle / SoC suspend changes have no physical battery or stability measurements.
- **Neither successful GitHub Actions nor a `STRUCTURAL_PASS_ONLY` report means flashing is safe.**

## Scope

Stay within `vorlocsev/galwear` only. Do not open upstream PRs or update upstream issues, do not merge into `main`, and do not deploy to a watch without a separate decision and validated recovery path.
