# tzlite known component audit

Baseline c5113789fb9572250ce6916634fd2c6e85f9e771: all seven
workflows passed. GPS host job 139768775961 in run 45778757818
confirmed 23 Tizen preflight cases and the restart configuration
failure case.

The legacy root-only mktzlite.py logs missing files and dependencies
but does not fail on them. Do not run it here. Add a separate
read-only auditor for the explicit known ELF set (10 programs,
12 plugin/library candidates from the legacy list). Check each
target's own closure, symbol scope, ARM ABI, interpreter and
executable mode, plus mountpoint directories and GNSS configuration.
The auditor is available via readiness --tzlite-root ROOT, which
is distinct from the prepared Tizen root containing mounted opt data.
Nine tests with mocked ELF audit and real filesystem fixtures pending CI.
This is not a full audit of arbitrary dlopen paths or all optional
configuration and data files. The legacy copier is unchanged;
no original donor tested, no privileged copies or actual mounts.
safe_to_flash=false.
