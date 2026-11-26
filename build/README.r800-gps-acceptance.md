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
phases make the runner exit nonzero. A host-only report cannot establish
vendor ABI compatibility, hardware readiness, independent reproducibility,
or safety to flash. Preserve the logs and report together.
