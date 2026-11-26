# GNSS foreground child identity

Baseline 39d7071a3bdf41928f004104afbe34f8e53178b2: 7/7 workflows.
GPS host job 139759819712 in run 45776041526 confirmed 11 startup
metadata tests and the synthetic SELinux binary policy gate.

Record direct child PPid and starttime from /proc/PID/stat immediately
after launch. Recheck them before considering a worker alive or
sending TERM/KILL. A live PID without matching evidence prevents
restart; cleanup remains bridge -> gpsd -> lhd. Preserve sensor-only
mode and restart budget. Eight actual host-shell disposable-process
tests pending exact-head CI. This reduces PID reuse risk but does
not provide atomic pidfd signaling, process-group/daemonized-child
tracking, or proof of original daemon readiness. Watch BusyBox
and original Tizen processes not tested. safe_to_flash=false.
