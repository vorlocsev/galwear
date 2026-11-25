# Integrated GPS gate: exact-blob host unit evidence

Tested source reference: aee09c6525e841da00f4015ff0b1a2daeaad2925.
On 2026-11-25, the following files were verified using git hash-object
against the GitHub content API blob SHA and executed on the native host:

```text
0dfe455723c27b94874216866fc83ca558a353dc build/r800_gnss_readiness.py
e63c0d2c9e68c3392ff5c638dfed5ddb86f7a3a3 build/r800_run_required_suite.py
90cfbb224a16f2bae5a85357838d26bc3902e672 tests/test_r800_gnss_readiness.py
c2c4b74d672471e41c4ab911d10c4039e1609da7 tests/test_r800_required_suite.py
```

Executed in an isolated four-file fixture:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/r800_run_required_suite.py 'test_r800_gnss_readiness.py'
PYTHONDONTWRITEBYTECODE=1 python3 build/r800_run_required_suite.py 'test_r800_required_suite.py'
```

- Readiness suite: 9/9 PASS, including contradictory markers and partial link input rejection.
- Required-suite runner: 5/5 PASS, including deliberately simulated empty, skipped, failing, and expected-failure suites. Diagnostic messages for those simulated failures are intentional.
- Both commands returned zero. No outer tests were skipped.

This evidence is limited to the four identified blobs, not a clean checkout
or full integrated-head regression. GitHub clone/ls-remote failed with
"Could not resolve host: github.com" in the execution environment. No donor
libraries or device runtime were exercised. No CI result is claimed.

Next: obtain a complete clean checkout, execute the full offline gate,
then separately verify donor glibc linking, QEMU and Android runtime.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
