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
