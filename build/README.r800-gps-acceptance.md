# R800 GNSS acceptance (NON-RELEASE)

Run from a trusted checkout on Linux x86-64 with Python 3, cc, pthread headers, Clang, LLD and GNU readelf.

```sh
python3 build/r800_gps_acceptance.py --out /tmp/r800-gnss-host-report
```

Choose a new output directory outside the checkout for each invocation.
The host phase runs six Python suites, seven native C builds and executions,
three ARM32 XTRA object builds and sixteen ARM32 synthetic HAL links.
The acceptance orchestration regression suite mocks subprocesses; it is not
independent evidence of native builds, ARM execution or GNSS functionality.
Earlier ELF/provenance regression suites remain separate CI steps.
No ARM executable or donor library is executed in the host phase.

For a local, unsigned experimental GPS Bridge with XTRA disabled, supply the
exact NDK r27c and a trusted, resolved local directory containing libc.so.6,
libdl.so.2, libpthread.so.0 and ld-linux.so.3 from Tizen:

```sh
python3 build/r800_gps_acceptance.py --out /tmp/r800-gnss-build-report \
    --ndk /path/to/ndk-r27c --donor /path/to/tizen-libs
```

Add `--qemu` only if you explicitly wish to execute synthetic guests using
trusted donor glibc. This requires an unprivileged user, qemu-arm-static and
bubblewrap with working namespaces. QEMU scripts build their own test
executables; they do not prove execution of the separately saved candidate.
No hardware devices or proprietary GNSS HAL are tested.

The report records PASS, FAIL, BLOCKED or NOT_TESTED for each phase, plus
requested source SHA-256, log hashes and the candidate hash if the build,
static re-audit and final candidate integrity check pass. REQUESTED_CHECKS_PASS is not a release gate or a
signature. Missing optional phases remain NOT_TESTED. Failed requested
phases make the runner exit nonzero. Successful host-only invocations
must contain exactly 43 check rows; successful donor invocations require 45
(with QEMU either explicitly requested or NOT_TESTED). Each successful
subprocess row must have exit code zero and a regular, non-symlink log
matching its recorded SHA-256. Missing, duplicate, unexpected or mismatched
rows and invalid PASS logs populate evidence_errors and force REVIEW_REQUIRED.
These checks validate local consistency only, not authenticity or a signature. A host-only report cannot establish
vendor ABI compatibility, hardware readiness, independent reproducibility,
or safety to flash. Preserve the logs and report together.


## Saved evidence verification

From a trusted checkout, verify the saved evidence directory without rebuilding
or executing the GPS Bridge:

```sh
python3 build/r800_gps_verify_report.py /tmp/r800-gnss-host-report --mode host
python3 build/r800_gps_verify_report.py /tmp/r800-gnss-build-report --mode donor --check-sources
```

Use `--mode qemu` if QEMU was requested. The expected mode must be
chosen independently of the saved report; do not downgrade a failed
requested phase to a host-only claim. The verifier checks the complete
successful matrix, status, non-release flags, log digests and saved
candidate digest. `--check-sources` additionally requires the exact source
manifest of the current checkout (older manifests can differ).
It exits 0 for CONSISTENCY_PASS and 2 for REVIEW_REQUIRED.
Consistency checks are not independent attestation of test execution:
a fabricated bundle with recomputed hashes may still pass. No vendor
ABI, hardware readiness, signature or permission to flash is established.


## CI evidence

The R800 GPS builder contract workflow runs the host-only acceptance matrix
and then verifies the saved report with `--mode host --check-sources`.
The artifact `r800-gnss-host-<commit-sha>-<run-attempt>` includes the
checkout SHA, available report and logs, and verifier output when that step
runs. Artifacts are retained for 14 days. Failed acceptance runs also
attempt artifact upload; an absent evidence directory is an upload error.
The workflow does not download donor libraries, execute QEMU, or publish a
flashable image. A missing artifact or unsuccessful workflow is not evidence
of acceptance. Use the actual workflow run and commit SHA when citing CI.
