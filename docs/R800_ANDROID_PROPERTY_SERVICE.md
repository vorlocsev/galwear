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


## Stock file_contexts and diagnostic init-domain transition

AOSP Android 11 SetupSelinux restores the label of /system/bin/init and
execs it to transition from kernel to init. The separate diagnostic
follows that sequence using the original libselinux and original
partition file_contexts, without calling setcon or setenforce.

    bash build/r800_aosp_selinux_transition_build.sh /absolute/aosp-r48 /absolute/new-transition-build

    python3 build/r800_qemu_selinux_transition.py \
      --init /absolute/new-transition-build/init \
      --compile-evidence /absolute/new-transition-build/initramfs-evidence.json \
      --kernel /absolute/property-kernel/arch/arm64/boot/Image \
      --baseline /absolute/property-boot-evidence.json \
      --config-evidence /absolute/virt-config-evidence.json \
      --stock-policy-report /absolute/stock-policy-boot.json \
      --product-out /absolute/product-out --checkfc /absolute/aosp-host/bin/checkfc \
      --out-dir /absolute/new-transition-boot --report /absolute/transition-boot.json

This independent archive contains the same static diagnostic binary at
/init and /system/bin/init, not stock init. Original file_contexts are
checked with host checkfc against the exact policy, then copied verbatim.
The required labels are u:object_r:init_exec:s0 and u:r:init:s0 after
exec, with enforcing=1. A failed restorecon, transition, or console
heartbeat rejects the gate. This does not label the entire Android
rootfs or launch the Android property service. Actual AOSP linkage,
ramdisk SELinux labeling, and guest execution remain unconfirmed.


## Expanded rootfs stock-policy relabel

Build the AOSP-linked static probe using the third argument relabel:

    bash build/r800_aosp_selinux_transition_build.sh /absolute/aosp-r48 /absolute/new-relabel-build relabel

The new build/r800_qemu_rootfs_relabel.py runner requires same-kernel
preflight, stock policy load and diagnostic domain transition reports,
the previous archive, the original preflight PID1, the staged tree and
the new relabel binary with its compile evidence. Use --help for the
complete argument list. It reconstructs the previous archive exactly
before replacing only the diagnostic /init and adding policy,
file_contexts and a bounded relabel manifest. The original system init
and property binaries remain present but are never executed.

For each selected system/partition/APEX/linkerconfig path and /dev/socket,
the probe uses Android libselinux lookup and restorecon, reads back the
label and compares it to the lookup. Missing contexts or denied relabel
are blockers, including potential APEX labels normally provided by its
filesystem image. This is not a general recursive labeling of every
virtual filesystem. The init executable and socket directory labels
are specifically checked when present.

Important policy constraint: Android 11 public/init.te contains
neverallow init { file_type fs_type }:file execute_no_trans.
A generic executable label on the experimental property client does
not authorize exec from init. Do not bypass this with setcon, permissive
mode, or arbitrary relabeling to init_exec. A subsequent test must use a
legitimate policy-authorized client domain and normal transition, or
report that the stock policy does not support the diagnostic harness.
No actual source build, relabel or property-service launch is established.


## Dedicated diagnostic client domain (modified policy, not stock)

    bash build/r800_aosp_galwear_policy_build.sh /absolute/disposable-aosp-r48 /absolute/new-fixture-policy

This recipe requires the same pinned clean AOSP checkout and a separate
output tree. It temporarily adds a private TE fragment and appends exact
file/property contexts; cleanup restores the original context files.
Use a disposable checkout only, since abrupt interruption may prevent
cleanup. It does not change or publish the original AOSP repository.
The AOSP policy build must retain neverallow checks. The static audit
checks the dedicated executable mapping and property labels, and rejects
a client listed as permissive by sepolicy-analyze.

The client enters its own coredomain via init_daemon_domain and verifies
its actual process context before any socket transaction. The fixture
permits debug.galwear.service and ro.galwear.service.fixture writes.
The latter must accept its initial value and reject a subsequent update.
debug.galwear.denied is seeded by the writer-owned Bionic area before
the service starts; the client may read it but cannot set it. Its
existing value must remain unchanged after the negative request.
ro.property_service.version receives a diagnostic-only exact mapping
to support reading protocol version 2 without granting broad default_prop
access. The overlay refuses existing exact keys rather than replacing
them. This is a deliberate change to platform policy, not a claim of
stock compatibility.

The build and client tests remain unverified in a real AOSP guest. The
next experiment must use the modified policy's own contexts, establish
a legitimate init-to-client transition, validate enforcing mode and
separate policy denial from read-only protocol errors. Prior stock
policy reports cannot establish acceptance of this modified policy.
No flashing, permissive fallback or blanket property write grant.


## Combined original property-service virt experiment

Build the diagnostic PID1 using the separate service mode:

    bash build/r800_aosp_selinux_transition_build.sh /absolute/aosp-r48 /absolute/new-service-boot service

Use build/r800_qemu_property_service.py --help for the full argument list.
It requires the prior stock rootfs relabel report, exact stock product
tree, the same staged original libinit harness/client binaries, and the
separately built GalWear fixture product tree. It reconstructs the
stock preflight archive and compares its digest before substituting
the fixture's audited contexts and policy. The fixture policy is not
the stock policy.

The fixture's explicit /system/bin/galwear_property_service mapping to
init_exec is reserved for the experimental PID1 harness. The guest
restores all selected labels, then execs only this harness. It never
execs original Android init. The service uses PropertyInit and
StartPropertyService from libinit and stops property-change dispatch
because the normal init event loop is absent. The client runs in its
dedicated domain, uses Bionic public APIs, and additionally checks
protocol-v2 raw replies for read-only (0x000b) and MAC denial (0x0018).
All expected markers and client exit status must precede heartbeat.
A transport failure alone cannot establish either rejection.

No build, relabel, policy transition, linker resolution or socket
transaction has been verified by a real guest yet. AOSP build/linkage,
RAM filesystem labels, inherited console permissions, boot default
properties, and kernel policy compatibility may still block execution.
No permissive fallback or production release.


## Sequential source-build and boot pipeline

Use a clean GalWear checkout and a clean disposable, already synced
AOSP Android 11 r48 checkout on Linux x86_64. The build phase creates
separate output trees for stock and fixture policy and the runtime,
libinit and diagnostic binaries. It may require substantial disk space.
The jobs option currently controls the runtime APEX build; the other
recipes retain their existing four-job defaults.

    python3 build/r800_property_pipeline.py build \
      --aosp-root /absolute/disposable-aosp-r48 \
      --out /absolute/new-property-build --jobs 4

Inspect service/init-dependencies.json and prepare an explicit choices
JSON using the documented rootfs selection contract. Do not choose a
conflicting library solely to make the run advance.

    python3 build/r800_property_pipeline.py boot \
      --build-root /absolute/new-property-build --choices /absolute/choices.json \
      --kernel /absolute/property-kernel/arch/arm64/boot/Image \
      --baseline /absolute/property-boot-evidence.json \
      --config-evidence /absolute/virt-config-evidence.json \
      --prepolicy /absolute/property-probe-evidence.json \
      --out /absolute/new-property-run

The boot phase requires previously accepted same-kernel property
baseline and pre-policy reports; kernel building and AOSP syncing are
not part of this runner. It requires the exact same clean GalWear commit
as the build phase and checks recorded report digests. Every stage has a
separate log and pipeline.json records stage status and evidence hash
where applicable. First failure stops later stages. Output directories
must not already exist. Re-run boot in a new output directory if inputs
need correction; automatic resume and full AOSP hosted CI are not enabled.
Only synthetic orchestration tests are added to lightweight CI.
No release, device operations, or claim of verified Android boot.


## Audit finding: kernel-domain full relabel is not a stock Android contract

Android init's initial kernel-domain restorecon of its own executable
is not authorization to restore every system, vendor or APEX path.
Android 11 policy typically assumes those partitions already contain
their labels. The exact compiled policy must be checked rather than
assuming permission from a related source tree.

Install host SETools (Ubuntu package setools) before the boot phase.
The new r800_rootfs_relabel_policy_gate.py invokes sesearch on the
audited stock policy for the necessary unconditional relabelfrom and
relabelto permissions for rootfs, init_exec and system_file. A missing
permission produces ROOTFS_RELABEL_POLICY_BLOCKED, exit 3, and an
explicit list in relabel-policy-gate.json. The combined pipeline stops
before expanded relabel. A successful query does not establish actual
filesystem xattr support, APEX labels, SELinux constraints or execution.

The intended alternative if blocked is a labeled read-only partition
image produced with the original file_contexts and Android image
tools, not a broad allow rule for kernel. This alternative has not
been implemented yet. The generic boot parser also rejects initramfs
unpack failures so embedded fallback cannot masquerade as a successful
external archive. Build phase evidence now requires exact expected
report paths and status names rather than trusting a saved status.

No actual compiled policy query, complete AOSP build, or QEMU boot has
been verified in this audit.


## Pre-labeled system EXT4 alternative (static only)

The initial implementation builds a small diagnostic /system image,
not a complete Android system partition. Supply a trusted AOSP host
e2fsdroid executable, checkfc, e2fsprogs and matchpathcon (for example
the selinux-utils package on Ubuntu).

    python3 build/r800_android_system_ext4.py \
      --staged /absolute/staged-rootfs --product-out /absolute/stock-product-out \
      --preflight-init /absolute/preflight-init \
      --checkfc /absolute/aosp-host/bin/checkfc \
      --e2fsdroid /absolute/aosp-host/bin/e2fsdroid \
      --out /absolute/new-system-fixture \
      --report /absolute/system-fixture.json

Only audited system entries and the platform file_contexts are copied.
The known linker alias is represented by a relative guest symlink.
The image uses a restricted EXT4 feature set and a fixed 128 MiB size;
it is not a signed, AVB-protected or flashable image. e2fsdroid applies
original platform contexts using the /system mountpoint; matchpathcon
independently determines expected labels by guest path and inode type.
The tool runs e2fsck -fn and uses read-only debugfs stat, ea_get and
dump to check each selected inode, actual security.selinux bytes and
file payload. No loop device or host mount is used. The image and
builder digest are recorded. The tool does not claim complete
filesystem enumeration or identical output across tool versions.

Remaining work: validate the actual host image tools and their
compatibility, add labeled vendor/product/system_ext as needed, preserve
the genuine APEX payload labels (not guessed platform contexts),
and build a separate generic virt kernel profile with a read-only
virtual block transport and EXT4. The existing property-profile
kernel and no-block QEMU acceptance contract remain unchanged.
No real e2fsdroid execution or kernel mount has been verified.


## Additional context partitions and original runtime APEX payload

    python3 build/r800_android_context_partitions.py \
      --product-out /absolute/stock-product-out \
      --checkfc /absolute/aosp-host/bin/checkfc \
      --e2fsdroid /absolute/aosp-host/bin/e2fsdroid \
      --out /absolute/new-context-partitions \
      --report /absolute/context-partitions.json

Each available system_ext, product, vendor or odm context partition is
a 32 MiB diagnostic ext4 image containing only the selected property
and file contexts. Missing optional partitions are reported, not
invented. The original policy is audited, each available context file
is checked with checkfc, and e2fsdroid receives the original context
files. Independent matchpathcon and debugfs checks cover selected
inodes and payloads. Conflicting or absent labels fail the build.
These are not complete Android partitions or hardware vendor blobs.

    python3 build/r800_android_apex_payload.py \
      --apex /absolute/com.android.runtime.apex --apex-sha256 EXACT_SHA256 \
      --staged /absolute/staged-rootfs --product-out /absolute/stock-product-out \
      --checkfc /absolute/aosp-host/bin/checkfc \
      --out /absolute/new-runtime-payload --report /absolute/runtime-payload.json

The APEX payload is preserved byte-for-byte, including any trailing
data. Selected original security.selinux attributes are read directly
from the filesystem; selected staged runtime binaries must match
their source payload. checkfc verifies that observed types exist in
the same policy. This does not verify AVB, APEX signature, every
inode, or Android APEX activation. Do not treat it as a replacement
for apexd. No host mounting or relabeling occurs.

Next: bind all image reports and exact hashes into a read-only
virtual disk manifest and introduce a separate virt kernel profile
with EXT4 and VirtIO block, leaving the existing no-block property
profile unchanged. Actual image-tool runs and guest mounting are
still unverified.


## Separate virtual block profile and read-only mount gate

The new block profile extends the property profile with built-in VirtIO
MMIO block, EXT4 and EXT4 security xattr support. The original minimal
and property profiles reject VirtIO block transport. Neither real
SM-R800 storage nor network devices are enabled. Use a fresh pinned
kernel checkout and the existing embedded diagnostic initramfs:

    sh build/r800_qemu_virt_compile.sh /absolute/kernel-source /absolute/galwear \
      /absolute/new-virt-block-kernel /absolute/embedded/initramfs.list block

First establish the existing embedded PID1 boot baseline on this exact
Image, without external disks. Compile the separate disk probe:

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      src/initramfs/virt-readonly-disks.c -o /absolute/disk-init
    python3 build/r800_initramfs_spec.py --init /absolute/disk-init \
      --list /absolute/disk-init.list --report /absolute/disk-compile.json

Then supply the three static image reports and their output directories
to build/r800_qemu_readonly_disks.py (see --help). The runner verifies
one shared policy SHA-256, matching context inventories, exact image
hashes and bounded regular-file input. It makes private copies, sets
them mode 0444, uses read-only raw blockdev/file nodes and only
virtio-blk-device, with no NIC. The guest resolves each image by unique
serial rather than MMIO discovery order, checks BLKROGET and mounts
under /mnt with MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC and noload.
It checks EXT4 magic and ST_RDONLY; host image hashes must remain
unchanged after the boot. The manifest slot is not the actual Linux
device name. No policy is loaded; this does not establish the guest
SELinux labels, Android root layout, AVB or service execution.

The block profile must still be compiled and tested on the pinned
kernel. Actual image creation, mount support and QEMU runtime are
unconfirmed. No release or flash artifact.


## Effective guest labels on pre-labeled Android mounts

The same read-only VirtIO transport now has a separate diagnostic
binary, compiled explicitly with GALWEAR_LABEL_PROBE:

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      -DGALWEAR_LABEL_PROBE src/initramfs/virt-readonly-disks.c -o /absolute/label-init
    python3 build/r800_initramfs_spec.py --init /absolute/label-init \
      --list /absolute/label-init.list --report /absolute/label-compile.json

Use build/r800_qemu_prelabeled_mounts.py --help. In addition to the
read-only disk runner arguments it requires the accepted no-policy
mount report, the matching product output tree and checkfc. The prior
mount report must identify the exact same kernel, configuration,
policy identity and ordered image digests/sizes. The new archive adds
the unmodified audited policy and a bounded exact label manifest.
The guest mounts system and available context partitions at their
Android paths and the original Runtime APEX at /apex/com.android.runtime,
without apexd or AVB activation. All mounts retain read-only, nodev,
nosuid and noexec flags, verified by statvfs.

After mounts are established, the diagnostic PID1 loads the audited
policy, requires enforcing=1 and the kernel domain, then compares
lgetxattr security.selinux on every selected path with the offline
label reports. No relabeling, setenforce or Android executable is used.
The unchanged image hashes and exact ordered console evidence are
required. If the stock kernel domain cannot inspect a mounted label,
the gate fails; do not widen kernel permissions to force acceptance.
This is a selected-inode test, not an audit of every filesystem inode.
The next gate must establish a legitimate init-domain executable
transition on labeled mounts, with only deliberately enabled execution.
Actual compilation, stock policy load and effective label readback
remain unverified.


## EXT4 diagnostic init-domain transition

This separate experiment replaces only canonical /system/bin/init
in a NEW system image with a static second-stage probe. Original
system image and original policy remain unchanged. Bootstrap-only
init layouts are rejected rather than guessing the entrypoint.

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      src/initramfs/ext4-init-domain-probe.c -o /absolute/ext4-second-stage
    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      -DGALWEAR_LABEL_PROBE -DGALWEAR_TRANSITION_PROBE \
      src/initramfs/virt-readonly-disks.c -o /absolute/ext4-first-stage

Generate the existing initramfs spec JSON for each binary with
r800_initramfs_spec.py. Build the separate system image using the
existing system image builder with --transition-init and
--transition-compile-evidence, pointing at the second-stage binary
and its spec. Its distinct status is ANDROID_SYSTEM_EXT4_TRANSITION_STATIC_ONLY.
The normal read-only and label-only runners reject this status.

Run build/r800_qemu_ext4_init_transition.py (see --help) with both
original and transition system image reports/directories, the accepted
original noexec labeled-mount report, both diagnostic binaries and
their compile evidence, and the same context/APEX images and stock
policy. The host requires matching selected inode metadata except
the explicitly substituted init payload hash. This compares selected
inode reports, not every byte or unlisted inode of the two images.

All disks remain read-only, nodev and nosuid. Only /system is mounted
without noexec; other partitions retain noexec. This allows execution
on the system mount, not an inode-specific noexec exemption. The
first stage loads stock policy and checks all selected labels before
execve of the fixed diagnostic path. The second stage checks PID 1,
u:r:init:s0, enforcing=1, /proc/self/exe, init_exec label and system
mount flags before heartbeat. No setcon, restorecon or setenforce
is used. The original init, dynamic linker and Property Service
are not executed. Stock policy may deny one of the diagnostic
checks; do not weaken the policy to make the test pass.

Actual image creation, compilation and guest execution remain
unverified. The next gate is a dynamic libinit service fixture with
its dedicated policy and separately audited executable mounts.


## Dynamic original Property Service on pre-labeled EXT4

The separate service fixture uses the previously built diagnostic
client policy, not the stock policy. Rebuild all image reports
against that policy (system, context partitions, preserved original
APEX payload). Use the same staged ELF files as the stock control.
The system image builder takes --service-fixture, mutually exclusive
with --transition-init, and adds the exact experimental single-namespace
config at /system/etc/ld.config.txt, the Android 11 linker fallback.
It requires explicit diagnostic client and init_exec service labels.
This is not generated Android linkerconfig; linker fallback selection
is not independently proven by the console markers.

    aarch64-linux-gnu-gcc -std=c11 -Wall -Wextra -Werror -O2 -static \
      -DGALWEAR_LABEL_PROBE -DGALWEAR_SERVICE_PROBE \
      src/initramfs/virt-readonly-disks.c -o /absolute/ext4-service-first-stage

Generate its initramfs spec as usual. Run
build/r800_qemu_ext4_property_service.py --help for the complete
arguments. A successful stock EXT4 static init-domain transition
report and original system image report are mandatory controls.
The runner compares the system binary/library inventory (including
aliases and modes) and the original APEX payload digest; the fixture
policy must differ from the stock policy. Audit the fixture with
checkfc and sepolicy-analyze, reject permissive init/kernel/client,
and require the exact fixture file/property context hashes.

All attached images remain read-only, nodev and nosuid. Both system
and runtime APEX need executable mappings for the dynamic linker
and libraries; other partitions retain noexec. After mounting disks
the first stage replaces devtmpfs with private RAM /dev and mounts
RAM /data, loads the fixture policy and checks all selected effective
labels. Only the fixed libinit harness is executed. The init-domain
harness restores the volatile /dev and /dev/socket labels, not
immutable disk files. The original property service and isolated
client must report all eight ordered protocol markers, including
distinct read-only and MAC errors, and then heartbeat.

The expected status is VIRT_GALWEAR_EXT4_PROPERTY_SERVICE_ONLY.
No full Android init, genuine generated linkerconfig, apexd, AVB,
physical watch or flash acceptance is implied. AOSP linkage, volatile
directory labeling, inherited console access, and service runtime
remain real-guest blockers until verified. Do not grant broad
permissions or relax enforcing mode to force the test to pass.


## Automated EXT4 property-service pipeline

The existing AOSP build phase now also builds host e2fsdroid in both
policy output trees. Use a clean GalWear checkout at the same commit
for build and boot. The EXT4 pipeline does not depend on successful
kernel-domain relabel of a RAM-only rootfs; it uses the separate
block-profile kernel and pre-labeled disk images.

    python3 build/r800_property_pipeline.py build \
      --aosp-root /absolute/disposable-aosp-r48 \
      --out /absolute/new-property-build --jobs 4

Prepare explicit library choices from service/init-dependencies.json,
compile the block-profile kernel and establish its no-disk embedded
PID1 baseline. Then:

    python3 build/r800_ext4_property_pipeline.py \
      --build-root /absolute/new-property-build --choices /absolute/choices.json \
      --kernel /absolute/block-kernel/arch/arm64/boot/Image \
      --baseline /absolute/block-baseline.json \
      --config-evidence /absolute/block-config.json \
      --out /absolute/new-ext4-run

The pipeline verifies the build report and exact commit, runtime APEX
path and digest, and exact block kernel evidence. It stages one rootfs,
compiles five separate static probes, builds stock image sets, checks
read-only mounts and guest labels, builds the separate static init
transition image, verifies its transition, then builds the diagnostic
policy image set and attempts the original libinit property service.
Each stage has an independent log and report hash. First failure stops
all later stages. Only the last successful gate produces
VIRT_EXT4_PROPERTY_PIPELINE_ONLY. The script requires substantial
local storage and host e2fsprogs, matchpathcon, ARM64 compiler and
QEMU. It does not sync AOSP, compile the kernel, or publish anything.

The AOSP build phase still includes the earlier RAM-only probe
builds; these are not used by the EXT4 boot phase. Actual complete
AOSP compilation, image creation, QEMU boots and CI are not yet
established. The new synthetic orchestration tests do not substitute
for a real run.


## Real CI entrypoints and evidence boundaries

r800-qemu-block-smoke.yml builds the pinned generic block kernel on
an Ubuntu hosted runner (same pinned Alpine LLVM toolchain as the
existing property workflow), boots its embedded PID1 without disks,
then creates two 16 MiB synthetic EXT4 files and runs the actual
read-only VirtIO probe. This does not depend on an AOSP checkout.
The push trigger is deliberately limited to changes to the workflow
itself on the development branch to start the first smoke run without
rebuilding the kernel for every code commit. The separate synthetic
status is VIRT_SYNTHETIC_READONLY_BLOCK_MOUNTS_ONLY; there is no
Android policy hash or Android acceptance report. Only JSON and
console logs are uploaded, not kernels, disk images or binaries.

r800-aosp-ext4-manual.yml is manual-only and needs a dedicated,
isolated Linux x64 self-hosted runner labeled galwear-aosp, with no
privileged credentials or shared sensitive workspace. Configure
repository variables GALWEAR_AOSP_ROOT (clean disposable pinned
AOSP checkout), GALWEAR_BLOCK_BUNDLE (directory containing Image,
block-baseline.json and virt-config-evidence.json for the exact
accepted block kernel), and GALWEAR_LIBRARY_CHOICES (explicit JSON
file). The runner must already have the build and QEMU prerequisites
and enough storage. No automatic source sync, kernel or AOSP artifact
download is performed. The confirmation input must be true. The
job is restricted to the development branch of this fork.

GitHub workflow_dispatch requires the workflow file on the default
branch; the new files are currently in the development branch only.
The block smoke push event does not require merging to main. Do not
merge or modify main merely to make the manual workflow dispatchable
without separate approval. The same full pipeline commands remain
available on a suitable Linux machine.

The workflow definitions and tests are committed, not evidence that
the runs passed. A successful synthetic block smoke does not establish
stock SELinux label handling, Android init, APEX activation or Property
Service. Full AOSP experiment acceptance requires its separate
VIRT_EXT4_PROPERTY_PIPELINE_ONLY report. No release or flashing.


## Native compile audit and guest failure localization

2026-11-25: exact Git blob f932670cdf440380c85e2fc2eaee6ab27bdba738
(virt-readonly-disks.c) and 46c585f5e7d4e5e5eee4303a8bf667e4a2ed9fce
(ext4-init-domain-probe.c) were verified against their retrieved source
bytes and compiled to x86-64 object files using GCC 14.2.0 with
-std=c11 -Wall -Wextra -Werror -O2 -c. All four valid first-stage
modes and the separate second stage compiled; service without labels,
transition without labels, and service plus transition were rejected
by the compile-time guards. No guest executable was run on the host.
This establishes native compilation only, not AArch64 compilation,
linkage with Bionic or a QEMU boot.

The disk probe reports explicit failure stages before exiting PID1.
Mount codes 3/4/5/6/7 identify serial resolution, device open, block
read-only verification, mount operation, and filesystem/flags checks.
Policy/label codes identify setup, policy load, enforcing/domain,
manifest parsing, xattr read, mismatch and final state. The generic
live observer rejects both explicit disk and label failure markers
immediately, preserving the failing diagnostic in the console.

The GitHub connector returned no combined statuses and no
PR-triggered workflow runs for the original block smoke commit.
That is not evidence that the push-triggered run is absent or failed.
Direct Actions retrieval and direct Git cloning were unavailable;
actual ARM64/EXT4/QEMU CI acceptance remains unverified.


## Python evidence boundary audit (2026-11-25)

The shared regular-file lookup now rejects absolute paths, traversal,
noncanonical path spelling, symlinked parents and symlink loops.
Baseline and bounded guest evidence reject duplicate JSON keys at
every nesting level rather than silently accepting the last value.
The system image builder verifies that the prepared property-context
hashes match the policy audit, rejects noncanonical guest paths,
and uses the same prepared rootfs snapshot for the experimental
linker configuration instead of reading the staged tree a second time.

Five isolated native Python unittest cases using copies of the revised
regular and unique_evidence_object function bodies passed (relative
paths, symlink parents/loops, nested duplicate JSON, top-level duplicate
JSON, ordinary JSON). This is not a full checkout test or an exact-head
CI result. The new repository test additionally runs ten actual CLI
--help subprocesses to exercise imports and argparse; compileall and
the new suite are wired into lightweight CI. The repository-wide suite
has not been executed in the current environment. GitHub cloning
failed DNS resolution and the public Actions API was inaccessible.
No kernel, QEMU, AOSP or hardware acceptance is inferred.


## Host filesystem tool compatibility audit (2026-11-25)

Android 11's canned_fs_config.cpp (AOSP android-11.0.0_r48) and
the Android 11-derived e2fsdroid/perms.c sources confirm that -C
selects a canned permission table; otherwise the default Android
fs_config may override mode, UID, GID and file capabilities. The
root key is represented by "/ " because e2fsdroid passes an empty
path for the filesystem root and the canned parser strips a leading
slash. All diagnostic partition builders now generate a bounded
canned table with exact staged permission bits, UID/GID zero and
capabilities=0. This deliberately is NOT production Android DAC
metadata. The selected-inode inspector requires exact mode and
ownership, rejects file capabilities, and still verifies the NUL-
terminated security.selinux bytes and the payload digest. The
generated table hash is recorded. e2fsdroid handles lost+found
separately; this remains a selected-inode audit.

The Android 11-derived e2fsdroid source confirms -e raw input, -S
context paths, -T timestamps, -a guest mountpoint, -f input tree,
and NUL-terminated label xattrs. The host matchpathcon source
confirms -N/-n/-f/-m mode lookup. debugfs ea_get -f writes raw bytes,
and stat reports the mode, owner, and fast-link destination.
Exact source-built e2fsdroid behavior still needs execution.

The new real host-tool tests create a synthetic disposable EXT4
image, write a test inode and label via debugfs, and exercise the
production read-only inspector. They check mismatched labels, mode
and UID, unchanged image hashes on readback, and matchpathcon
file-type selection. CI installs selinux-utils and e2fsprogs.
Neither tool suite is installed in the current execution container;
no real host-tool test or CI success is claimed.

An additional kernel-source blocker is now explicit: pinned
security/selinux/hooks.c at 50db73fc799f20a7120a8b5f653b16cc123d856f
checks nosuid/NNP during a domain-changing exec. An unapproved
transition can fall back to the old SID. Read-only executable mounts
currently retain nosuid. The next acceptance audit must inspect
compiled policy capability nnp_nosuid_transition, process2
nosuid_transition permissions and any applicable type bounds for
kernel->init and init->galwear_property_client. Source declarations
alone do not prove these permissions. Do not relax flags or policy
to manufacture a successful transition.


## Compiled nosuid transition prerequisite audit

The pinned kernel security/selinux/hooks.c check_nnp_nosuid()
permits domain-changing exec on a nosuid mount if the compiled
policy has nnp_nosuid_transition and allows process2
nosuid_transition, or if security_bounded_transition() in
security/selinux/ss/services.c finds the old type in the new
type's bounds ancestry. The latter walks the entire ancestor chain.
A denied default transition can fall back to the old SID.

The standalone read-only audit is:

    python3 build/r800_ext4_nosuid_policy_gate.py \
      --product-out /absolute/stock-product-out \
      --checkfc /absolute/host/bin/checkfc \
      --profile stock --report /absolute/stock-nosuid.json

Repeat with --profile fixture and the fixture product output.
The stock profile checks kernel -> init via init_exec. The fixture
also checks init -> galwear_property_client via its dedicated
entrypoint type. The audit uses SETools seinfo --flat --polcap and
--typebounds, and sesearch for unconditional type_transition,
file execute, process transition, file entrypoint and process2
nosuid_transition. It checks direct and inherited typebounds.
Conditional allow rules are deliberately not accepted by this
conservative gate. Absence of a required unconditional rule does
not prove a runtime denial under every possible Boolean state.

Exit 0 / EXT4_NOSUID_POLICY_PREREQUISITES_ONLY means static
prerequisites were found, not a successful kernel AVC decision.
Exit 3 / EXT4_NOSUID_POLICY_PREREQUISITES_NOT_MET means the
conservative prerequisites were not met; exit 2 / REJECT is
an invalid input or tool failure. MLS, constraints, file access,
inherited descriptors, NNP and actual exec remain runtime checks.
The pipeline records stock and fixture reports separately before
building each executable experiment. Both direct QEMU runners
also repeat the audit on the exact policy bytes destined for
the guest archive; a prior JSON report cannot bypass the check.

Mount flags and policy rules are unchanged. No generated permissions
or typebounds are added to force a pass. SETools CLI syntax was
checked against the 4.5.1 source; actual compiled AOSP policy and
SETools binaries are absent from the current environment. Eight
mocked regression cases are committed, not executed here.


## Executable access and inherited stdout observations

The pinned kernel hooks.c file_has_perm() checks FD__USE when
the descriptor opener SID differs from the current SID. During a
domain-changing exec, flush_unauthorized_files() revalidates inherited
descriptors and may replace unauthorized ones with the SELinux null
file. Its mmap hooks also check file map, read and execute permissions
for executable file-backed mappings.

The new r800_ext4_exec_access_audit.py reports unconditional TE
allow candidates for kernel/init-owned descriptors, assumed console
inode types, and actual selected system/runtime ELF inode types from
the matching policy-bound image reports. It deduplicates queries by
source, target, class and permission, retaining candidate paths.
The stock profile covers the console assumptions only; the fixture
profile adds both init and client ELF access, including the linker
alias. The result is advisory: a missing candidate permission is
not a proven AVC denial, because actual library selection, SID of
the opener, inode type of the console, conditionals and constraints
are not established by this audit. Both EXT4 execution runners
repeat it on the exact guest policy snapshot. No rules are added.

For the actual guest, the first-stage disk probe now reports
fstat(stdout) character device, inode and filesystem device. Static
second-stage init, the libinit harness and its client report the
same fields after exec. The EXT4 runners require ordered markers
and the same /dev/console device (5:1), inode and filesystem device
throughout the corresponding handovers. These are guest observations,
not proof of opener SID or open-file-description identity. Other
RAM-only parsers can ignore the additional marker. Failure to observe
the console rejects the EXT4 experiment rather than inferring
success from missing output. No broad fd or console grants, mount
flag changes, or SELinux relaxation are made.

Six new synthetic access/console tests and two updated transition
regressions are committed. The new C/C++ code, tests and actual
compiled AOSP policies have not been tested in the current
environment. The exact runtime console and dynamic loading remain
unverified. No real watch, upstream repository or main branch changes.


## Static selected-inventory linker resolution (2026-11-25)

Android 11 Bionic linker.cpp at android-11.0.0_r48 confirms the
configuration search order (architecture, generated, VNDK-specific,
then /system/etc/ld.config.txt for these system executables; APEX
executables and debug builds may use other paths). Library lookup
also considers previously loaded SONAMEs, LD_LIBRARY_PATH, RUNPATH,
a bootstrap fallback in non-APEX builds, and namespace paths. The
diagnostic entry points use an empty environment and reject embedded
RPATH/RUNPATH in the inspected files. The configured experimental
namespace searches bootstrap, system, then Runtime Bionic directories.
This is an explicit restricted model, not a complete emulation of
the linker or proof that Bionic selected that configuration.

Preflight now retains the inspected ELF metadata and explicit
selection map. System and preserved APEX reports bind those records
to verified file digests. The entire original APEX is mounted, so
the model includes all four already audited APEX ELF files, not only
the files selected for the staged RAM rootfs. The separate
r800_ext4_linker_resolution.py checks the exact fallback config,
resolves the allowed linker alias, walks DT_NEEDED from each of the
two service/client entry points, and rejects any candidate precedence
that differs from the chosen path. Every selected ELF must be
present in the image inventory with matching digest and metadata.

The pipeline records EXT4_LINKER_RESOLUTION_STATIC_ONLY before
attempting the service. The direct service runner repeats the model
and includes its result. It does not prove symbol availability,
symbol versions, relocations, late dlopen, actual namespace
selection, or the absence of uninspected APEX files. Full image and
runtime evidence remain separate. Eight synthetic regressions are
added to CI; not executed here. Rebuild earlier image reports to
include the new ELF fields. No Android or hardware boot claim.


## Static ELF ABI and relocation inventory

r800_ext4_elf_abi.py re-extracts selected ELF objects from the
read-only system and Runtime EXT4 images via debugfs, checks their
digests against the previous resolution model, inspects GNU readelf
dynamic symbols, version needs and relocation tags, and rechecks
both images after inspection. No full symbol tables are stored in
the image reports. The audit counts missing strong and weak symbol
candidates separately and records examples, symbol version provider
SONAME, default-version compatibility, TLS type mismatch and
multiple provider candidates. Matching exports are not actual
Bionic lookup or evidence of a correct symbol address. Missing
candidate counts are advisory because linker-supplied symbols,
visibility and lookup scope require runtime interpretation.

The pinned Bionic android-11.0.0_r48 source supports AArch64 RELA,
Android packed RELA and RELR; REL and text relocations are rejected
by the static check. The report records numeric Android dynamic
tags and visible relocation types, but does not decode packed
relocations, prove relocation correctness or exclude API stubs.

Native container smoke: clang/lld cross-compiled two freestanding
AArch64 Android-target synthetic shared objects with a versioned
fixture@GALWEAR_1 import and fixture@@GALWEAR_1 export. GNU readelf
2.44 showed the version need provider libfixture.so and
R_AARCH64_JUMP_SLOT. A separate synthetic packed-RELA ELF showed
OS-specific tags 0x60000011 and 0x60000012 despite readelf saying
there were no relocations. These tool observations were executed,
not the new repository suite or actual AOSP image audit.

The pipeline saves EXT4_ELF_ABI_STATIC_ADVISORY_ONLY and the
direct service runner repeats the audit. Nine regression tests
(including a real synthetic cross-target ELF compile/readelf test)
are added to lightweight CI. Full CI, actual Android libraries,
Bionic relocations, AOSP compilation and guest execution remain
unverified. No stub-exclusion or flash acceptance claim.


## Binary AArch64 relocation structure audit

The selected ELF ABI inspection now also decodes ordinary RELA,
PLT RELA, Android APS2 packed RELA, and both standard and Android
RELR encodings directly from PT_DYNAMIC and PT_LOAD, independent
of section names and GNU readelf's packed relocation support.
The Android 11 r48 linker_reloc_iterators.h and linker.cpp define
the grouping flags, running addend and RELR bitmap semantics.
The diagnostic decoder is intentionally conservative: bounded
SLEB128, nonzero bounded groups, exact stream consumption, unique
file-backed table mappings, supported relocation types, dynsym
index bounds, and nonoverlapping write targets entirely within
writable non-executable PT_LOAD segments. It rejects unsupported
REL, COPY, text relocations and conflicting relocation encodings.
It never applies a relocation. Some legal but unusual ELF layouts
may be rejected by these diagnostic restrictions.

Actual native host check: the tested Python module's Git blob
d43a14f725a16fa1359a0f31608b7184c7da7b3a matches the repository
blob. Clang/LLD cross-compiled four freestanding AArch64 Android
API 30 ELF files, and GNU readelf supplied their dynamic symbol
counts. The module decoded exactly five relocations in every case:
none (four RELA RELATIVE, one RELA ABS64), android (four APS2
RELATIVE, one APS2 ABS64), relr (four RELR RELATIVE, one RELA ABS64),
and android+relr (four RELR RELATIVE, one APS2 ABS64).
These four actual decoder smoke checks passed. No ELF was executed.
The new nine-case regression suite, including these four encodings
in its cross-target test, is wired into CI but the full suite and
actual AOSP disk image audit have not been executed here.

The ABI report includes structural counters per selected object.
Successful decoding does not prove runtime relocation arithmetic,
symbol resolution, IFUNC/TLS behavior, ABI compatibility or stub
exclusion. API stubs can have plausible dynamic symbol tables.
The latter requires independently bound implementation build
provenance and/or runtime behavioral evidence, not a heuristic
that declares an ELF non-stub because it has relocations.


## AOSP installed artifact origin

Android 11-derived Soong cc/cc.go IsInstallableToApex explicitly
excludes stub variants and versioned SDK libraries. cc/library.go
distinguishes the generated stub compilation path from implementation
builds and installs Bionic implementation variants in bootstrap
locations. This source evidence explains why installed product paths
and the built runtime APEX are preferable to arbitrary Soong
intermediates, SDK exports or a symbol-count heuristic. It does not
independently establish which variant a particular local build used.

The runtime and service build recipes now include the exact resolved
manifest digest in their hash-bound extraction and dependency reports.
The origin stage checks those reports through verify_build, requires
matching manifest XML with explicit project revisions, validates the
runtime APEX identity inside the dedicated build tree, and compares
every selected staged ELF's digest and size with the recorded build
graph and original installed/extracted file. Runtime choices must
also match the original APEX extraction metadata. Only supported
installed product paths and selected Runtime APEX paths are accepted;
intermediate SDK paths and substituted source aliases are rejected.
No new AOSP checkout, module-info format or Ninja rule is assumed.

The EXT4 pipeline records AOSP_SELECTED_ARTIFACT_ORIGIN_ONLY before
building images. The direct service experiment additionally requires
--origin-report and checks the staged ELF inventory plus APEX and
payload hashes against it. Rebuild older AOSP evidence to include
the resolved manifest digests. The provenance is local, unsigned,
and assumes the isolated build environment is trustworthy. It is
not an independent Soong variant attestation or proof of non-stub
behavior. stub_exclusion_proven remains false. Seven synthetic
regressions are added; execution of these tests, actual AOSP build
and QEMU service acceptance are not confirmed.


## Functional Bionic client acceptance

The diagnostic property client now checks calloc zero initialization,
realloc preservation, writes to the expanded buffer and free; a real
pthread create/join, independent pthread-specific key values and
thread-local errno; direct libm sqrt and dynamic libdl lookup via
RTLD_NOLOAD, dlsym, dladdr, dlclose; and negative dlsym/dlerror
behavior. The client links libdl and libm explicitly. All checks run
after the client domain/protocol observation and before its first
property socket write. They use bounded allocations and no external
network or additional property grants.

Both RAM and EXT4 service parsers require exactly the four ordered
r800-bionic markers in that window. The EXT4 runner additionally
compares the reported libm provider path with the selected client
ELF dependency graph. This is guest-reported behavior, not a
comprehensive verification of every Bionic API, native ELF TLS
relocations, or independent proof of all library implementations.
The new thread and loader behavior may reveal further SELinux
or runtime prerequisites. No SELinux rules are relaxed.

Actual host verification: eight isolated Python console-contract
tests passed after fixing a wrong-order test fixture which had
accidentally reconstructed its original sequence. Both files were
checked against their repository Git blobs:
94e9ba01989ebd796f795c4d8ff9fd4b538f4b7d
(contract) and c3046b20a3e27df8d3443a6a9c6724b6ca25f8a4
(tests). This was not a full checkout test or AOSP compilation.
The new C client has not been built against Android 11 or executed
in QEMU. Old property-only logs cannot pass the new contract.
Rebuild the service and image artifacts at the current source commit.
Full CI, actual Bionic execution, and real SM-R800 boot remain
unconfirmed; safe_to_flash remains false.


## Kernel thread/event prerequisite (pre-policy block profile)

The Android 11 r48 system/core/init/property_service.cpp starts
a pthread-backed PropertyServiceThread using Epoll::Open,
epoll_create1, epoll_ctl and epoll_wait. The pinned Linux 4.19
source (50db73fc799f20a7120a8b5f653b16cc123d856f) exposes EPOLL and
EVENTFD as configurable symbols in init/Kconfig. The previous
allnoconfig overlay did not explicitly request EPOLL. This is a
configuration risk, not an observed ENOSYS failure. The property
and block profiles now explicitly enable EPOLL and EVENTFD; the
effective-config contract requires them and the MMU. The generic
minimal and hardware profiles are not changed to add event support.

Bionic r48 pthread_create.cpp uses mmap/mprotect, CLONE_SETTLS,
CLONE_PARENT_SETTID and CLONE_CHILD_CLEARTID; pthread_join.cpp
waits on the TID futex. The pinned arm64 process.c implements
CLONE_SETTLS and TLS context switching. The new static glibc
diagnostic PID1 tests an anonymous 4 KiB mapping, protection
change and unmapping; raw FUTEX_WAIT_PRIVATE mismatch (EAGAIN)
and timeout (ETIMEDOUT); actual FUTEX_WAKE_PRIVATE of a waiting
pthread with independent C thread-local state; eventfd readiness,
epoll delivery and drained readiness. No Android policy or
property service is initialized in this diagnostic.

Actual native host evidence: GCC 14.2.0 x86-64 with
-std=c11 -Wall -Wextra -Werror -O2 -pthread and GALWEAR_HOST_TEST
compiled and ran the source, then a further ten repeated runs
passed (10/10). The ordinary guest-mode source also compiled
with -static on x86-64 and was not executed on the host.
The verified source Git blob is
3d8cf864567f65ab318f622be2a8c3fbdaa87915.
This is not ARM64 or the pinned Linux kernel test.

r800_qemu_thread_event.py binds its guest evidence to the exact
compiled block profile and embedded PID1 baseline. The Block
Smoke workflow and full EXT4 pipeline now run it before disk
experiments and retain VIRT_BLOCK_THREAD_EVENT_ONLY separately.
Five synthetic console/config test cases and a native host smoke
are wired into CI. The new ARM64 compile, QEMU boot, full CI and
actual Bionic execution remain unverified. Recompile the block
kernel using the revised effective config. No SELinux, hardware
kernel or firmware changes, no flashing.
