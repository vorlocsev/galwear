# Android 11 property service preparation (generic virt only)

The dynamic NDK probe now uses the real public Bionic APIs
__system_property_find and __system_property_read_callback. The default
mode expects an absent debug.galwear.probe property. It does NOT prove
that a property area or a property service exists. The separate
--expect-property mode requires debug.galwear.probe=ready and exactly
one matching callback; the current supervisor does not select this mode.

Source references (pinned android-11.0.0_r48):
- https://android.googlesource.com/platform/system/core/+/refs/tags/android-11.0.0_r48/init/property_service.cpp
- https://android.googlesource.com/platform/system/core/+/refs/tags/android-11.0.0_r48/property_service/libpropertyinfoserializer/
- https://android.googlesource.com/platform/bionic/+/refs/tags/android-11.0.0_r48/libc/bionic/system_property_api.cpp

## Metadata fixture

Use the dedicated synced AOSP checkout from R800_AOSP_RUNTIME_BUILD.md:

    bash build/r800_aosp_property_info.sh /absolute/aosp-r48 /absolute/new-property-evidence

The script creates a temporary host-tool Soong module, builds it against
the AOSP serializer/parser and removes the source overlay. The fixture
serializes a single exact property name and the default string context,
then reads the result back using the AOSP parser. The output is
property_info and a digest record, not a property area or service.

## Remaining real property service prerequisites

- The minimal QEMU virt profile still forbids CONFIG_NET. The separate
  property overlay enables NET, UNIX, INET, AUDIT and SELinux because
  this pinned kernel explicitly requires INET for SELinux. NETDEVICES,
  IPv6, packet sockets, netfilter and other selected protocols are forbidden.
  QEMU still runs with -nic none. IPv4 loopback remains possible; this is
  not a kernel without networking. SELinux disable/development options
  are forbidden; an actual policy must still be built and loaded.
- PropertyInit creates /dev/__properties__/property_info and calls
  __system_property_area_init. The latter reports failure on failed
  SELinux label writes. The guest needs a compatible SELinux setup
  and a writable RAM-backed property directory.
- Build actual Android init and its dependency closure from AOSP.
  A property context fixture is not a production SELinux policy.
- Start the real service; test an authorized write, a read in a separate
  process, update notification and rejection of an unauthorized write.
  Do not replace the real service with a mock and report Android success.

No real property area, property service, Android init or watch boot has
been confirmed. No change to the six-entry base initramfs or hardware
configuration. safe_to_flash=false.

## Separate kernel profile

In a fresh disposable pinned kernel checkout, use the existing virt build
recipe with the optional final argument property. CI workflow
r800-qemu-property.yml compiles the resulting profile and attempts the
embedded minimal PID1 boot. Configuration and boot evidence do not establish
SELinux policy loading, property labels or AF_UNIX service behavior.


## Original libinit service build (not booted)

    bash build/r800_aosp_init_service_build.sh /absolute/aosp-r48 /absolute/new-init-evidence

This recipe builds the original init_second_stage target alongside a
temporary test module linked to the unmodified libinit. The harness invokes
PropertyInit and StartPropertyService directly, then execs a separate Bionic
client that uses __system_property_set, reads properties and tests the
read-only version property. It does not replace the server protocol.
The build inventory records the direct ELF dependencies and interpreter
for all three executables; the complete runtime dependency closure is not
yet resolved. The temporary Soong overlay is removed after the build.

Do not run the harness on a real Android device or host. For a future virt
run it requires a fresh RAM-backed /dev, /dev/socket, procfs, sysfs,
matching Android property contexts and an appropriate enforcing SELinux
policy, plus a verified linker namespace and library closure. The current
synthetic base_t fixture is not that policy. The harness requires PID 1
and the explicit --virt-property-service argument. It does not implement
the normal init event loop, persistent-property handling or ctl.* services.
Read-only rejection is not evidence of SELinux authorization denial.

No original init or original property service execution is established by
the build recipe or inventory alone.

## Recursive native dependency inventory

The init source build recipe accepts an optional third argument: the extracted
runtime root from R800_AOSP_RUNTIME_BUILD.md. The output init-dependencies.json
walks DT_NEEDED recursively, including cycles, across system/lib64,
system/lib64/bootstrap and apex/com.android.runtime/lib64/bionic. It records
separate candidates and digests, missing libraries, different-content copies
and available linker executables. It never follows Android absolute symlinks
into the host. Candidate count and total bytes are bounded.

This is not a linker namespace resolver. A missing candidate may require
another APEX or partition, and identical copies do not establish correct
namespace selection. No library is chosen automatically on ambiguity.
DT_NEEDED does not include every dlopen dependency; actual linker config,
bootstrap transitions, Android property contexts and sepolicy remain required.


## Experimental single-namespace rootfs staging

Create a selection JSON based on init-dependencies.json. Example schema
(the linker must actually exist in the audited candidate inventory):

    {"libraries": {}, "interpreters": {"/system/bin/linker64": "runtime:apex/com.android.runtime/bin/linker64"}}

Specify a library candidate key under libraries for each reachable
different-content conflict; do not guess the correct version. Every
PT_INTERP requires an explicit audited linker choice.

    python3 build/r800_android_init_rootfs.py \
      --product-out /absolute/product-out \
      --runtime-root /absolute/runtime-root \
      --choices /absolute/choices.json \
      --out /absolute/new-staged-rootfs \
      --report /absolute/rootfs-plan.json

The tool recomputes the candidate graph, traverses selected dependencies,
checks SHA-256 again before writing, and stages regular non-executable files
only. Guest linker aliases are recorded as data, not created on the host.
The linker config is an experimental single namespace; it is not generated
Android linkerconfig policy and does not reproduce all bootstrap/APEX
namespace rules. No Android executable is launched. Actual namespace
behavior, other APEX dependencies, property contexts, sepolicy and guest
mount preparation remain unverified.


## Rootfs archive preflight

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      src/initramfs/android-rootfs-preflight.c -o /absolute/preflight-init

    python3 build/r800_android_rootfs_preflight.py \
      --staged /absolute/staged-rootfs --product-out /absolute/product-out \
      --init /absolute/preflight-init --archive /absolute/preflight.cpio \
      --report /absolute/preflight.json

Repeat the same command with --verify to compare an existing archive against
the canonical reconstruction. The archive is limited to 64 MiB. The
original six-entry CPIO audit is unchanged. AOSP platform property contexts
are mandatory; optional partition contexts are included only if available
as regular files at the exact partition paths. No context text is synthesized.
The files are not validated against Android SELinux policy yet.

The static diagnostic PID1 mounts procfs, sysfs, devtmpfs and a small tmpfs
on /data and creates /dev/socket in the guest. It checks the staged client
and service file permissions without executing either. No Android property
area, policy or service is started. The QEMU runner binds the archive to the exact property-profile Image and requires ordered preflight markers.
Keep all binary inputs and archives private and disposable; do not flash.


## QEMU rootfs preflight acceptance

After successful embedded property-profile boot and pre-policy diagnostics
on the same Image, run the canonical archive in an isolated guest:

    python3 build/r800_qemu_rootfs_preflight.py \
      --staged /absolute/staged-rootfs --product-out /absolute/product-out \
      --init /absolute/preflight-init --archive /absolute/preflight.cpio \
      --kernel /absolute/property-kernel/arch/arm64/boot/Image \
      --baseline /absolute/property-boot-evidence.json \
      --config-evidence /absolute/virt-config-evidence.json \
      --prepolicy /absolute/property-probe-evidence.json \
      --out-dir /absolute/new-rootfs-preflight-boot \
      --report /absolute/rootfs-preflight-boot.json

The runner reconstructs the archive rather than trusting saved JSON and
compares it byte-for-byte. The kernel digest must match all prerequisite
reports. QEMU has no NIC, block devices or host directory mounts. Success
requires exact ordered preflight markers and the existing platform/heartbeat
contract. Unexpected property-service or policy diagnostics are rejected.
Guest checks include regular-file types, modes, root ownership and linker
configuration presence. Neither actual linker execution nor Android policy
compatibility is established by this test. CI checks the synthetic runner
contracts and compiles the static preflight PID1; a real AOSP-backed boot
remains a separate experiment.


## Original AOSP sepolicy static preflight

    bash build/r800_aosp_sepolicy_build.sh /absolute/aosp-r48 /absolute/new-policy-build

The recipe requests stock selinux_policy and host checkfc from the pinned
manifest. It does not modify or install SELinux policy on the host.
If the selected product does not install a precompiled split policy or
its partition hash files, the audit rejects it. No fallback to the
synthetic policy or automatic policy downgrade is permitted.

For the exact product tree used to stage the rootfs, run:

    python3 build/r800_android_sepolicy_audit.py \
      --product-out /absolute/product-out --checkfc /absolute/aosp-host/bin/checkfc \
      --rootfs-report /absolute/rootfs-preflight-boot.json \
      --report /absolute/sepolicy-audit.json

The explicit checkfc executable must be trusted and source-built; its
digest is recorded, not independently authenticated. The audit checks
the binary MLS header (kernel versions 19 through 31), ODM/vendor
precompiled selection, system/system_ext/product policy ID agreement,
and validates each available property_contexts file with checkfc -p.
The optional rootfs report must contain the exact same context hashes.
Matching partition IDs are not recomputation of the original CIL hashes.
This is a static check, not evidence of actual kernel policy load,
file labeling, service permissions, enforcing access or full Android boot.


## Stock Android policy load experiment

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      src/initramfs/android-stock-policy-probe.c -o /absolute/stock-policy-init
    python3 build/r800_initramfs_spec.py \
      --init /absolute/stock-policy-init --list /absolute/stock-policy-init.list \
      --report /absolute/stock-policy-compile.json

    python3 build/r800_qemu_android_stock_policy.py \
      --init /absolute/stock-policy-init --compile-evidence /absolute/stock-policy-compile.json \
      --kernel /absolute/property-kernel/arch/arm64/boot/Image \
      --baseline /absolute/property-boot-evidence.json \
      --config-evidence /absolute/virt-config-evidence.json \
      --rootfs-report /absolute/rootfs-preflight-boot.json \
      --rootfs-archive /absolute/preflight.cpio \
      --product-out /absolute/product-out --checkfc /absolute/aosp-host/bin/checkfc \
      --out-dir /absolute/new-stock-policy-boot --report /absolute/stock-policy-boot.json

The runner repeats the static stock policy audit and compares contexts and
the exact previous rootfs archive with same-kernel preflight evidence. It
boots a separate minimal archive containing the diagnostic PID1 and the
unmodified audited policy bytes. The expanded Android rootfs is not mounted
during this test. A successful load must retain enforcing=1 and report
the initial u:r:kernel:s0 domain. No setenforce, setcon, Android exec or
file relabel is attempted. Failure to access the console, enforce or
proc attr after the policy is loaded is a failed diagnostic, not a reason
to weaken policy. The next gate must validate original file_contexts and
the normal kernel-to-init executable transition on an expanded guest.
Actual stock policy compilation and execution remain unconfirmed.
