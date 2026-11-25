# R800 media PCM/ABOX retry (NON-RELEASE)

Base 503746abe1a937cb05586a8d12f3cca8831c68ff, six CI checks passed including PCM source ABI comparison.
Historical kernel ABOX firmware delayed work already retries every 2s;
this change does not modify kernel DSP power or firmware retry logic.

Media input/output now treat route mixer failures as start failures,
do best-effort route rollback, never open PCM after a failed route,
close failed handles and set standby. Retry deadline is measured after
cleanup; read/write failure also starts the 1s cooldown. HFP ownership
check unchanged; normal successful open clears retry deadline.
Host tests compile actual start functions and inject seven failure
cases (route, gain, open and readiness), verify rollback, cooldown,
HFP exclusion, and eventual successful retry.

Remaining: partial mixer rollback cannot guarantee all registers restored,
simultaneous media route changes, DSP readiness and actual firmware
power-cycle behavior unverified. No hardware calls or flash performed.
safe_to_flash=false.
