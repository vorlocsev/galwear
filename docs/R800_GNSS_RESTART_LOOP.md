# GNSS restart loop integration

Baseline e06569062bf8f9487716608f127df8f665279040: 7/7 workflows.
GPS host job 139762476578 in run 45776855704 confirmed eight
identity and five real-process crash/cleanup tests.

Extract the production restart loop as a shell function with device
adapters. Production retains 20 attempts, lhd/gpsd delays, ownership
recovery, IPC metadata gates and reverse cleanup order. Background
adapters exec the chroot worker. Skip unnecessary retry delay after
the final attempt. Tests execute the same loop with disposable
foreground workers, shortened delays, and two attempts: persistent
IPC failure, recovered IPC, lost IPC before bridge, failed ownership
preparation, lhd failure, gpsd failure and bridge failure budget.
Seven new tests pending CI. This does not execute actual chroot,
firmware, BusyBox or GNSS hardware. No policy changes or flash.
safe_to_flash=false.
