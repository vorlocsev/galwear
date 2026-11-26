# Samsung GNSS registration candidate

Baseline 8ad9bdecf940c68176f895f27c78bb47000e35ef passed 7/7 workflows.
GNSS run 45773492021 host job 139751473621 confirms 19 donor gate tests
and the explicit QEMU input test.

The existing mk_vendor_gnss.sh describes the J4 Samsung service registering
standard IGnss and proprietary ISecGnss. The former static auditor accepted
only the AOSP executable, and IPC identity used the same incorrect restriction.
Support either one AOSP service or one Samsung J4 candidate with both unique
HIDL 1.0 declarations. Reject competing services, extra/wrong interfaces,
duplicate services and disabled services without all declared lazy interfaces.
Require the Samsung wrapper, implementation and interface library in addition
to the standard wrapper/module/interface library. Require direct interface
dependencies conservatively; actual J4 ELF may require further review.
Use the same service selector for UID/GID candidates.
Seven new synthetic tests pending CI. No change to vendor image builder,
SELinux policy, init startup or runtime credentials. Original Android/Tizen
images absent; no actual registration or hardware verification.
safe_to_flash=false.
