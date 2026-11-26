# Supervisor crash and restart fixtures

Baseline 191fbdb5f9d91f614014505c5266e80bb1c811c8: seven workflows
successful. GPS host job 139761019044 in run 45776410191 confirmed
eight child identity tests. Strengthen negative shell assertions:
a negated command is exempt from errexit, so use explicit failure.

Five additional host tests run the actual helper functions and
signal traps with disposable foreground workers: SIGKILL lhd,
gpsd or bridge; TERM-ignoring bridge escalation; supervisor TERM.
Check surviving worker stop order and disappearance before a new
stack is started. The restart is driven by the fixture, not the
full Android helper loop; the real chroot, BusyBox and proprietary
daemon behavior remain untested. No hardware or flash changes.
Tests pending exact-head CI. safe_to_flash=false.
