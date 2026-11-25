# SM-R800 GNSS registration preflight

Repository evidence: the vendor manifest declares android.hardware.gnss@1.0
IGnss/default over hwbinder. payload/start.sh binds the GPS HAL into
/vendor/lib/hw/gps.r800.so and maps p17 to /oem. Neither a manifest declaration
nor a mount command proves that hwservicemanager has registered the HAL.

Run against a clean, assembled, offline Android system-as-root tree:
```sh
python3 build/r800_gnss_registration.py --root /path/to/assembled-root
```

The audit expects the selected 32-bit vendor service, implementation in
vendor/lib/hw, HIDL interface library in vendor/lib, and exported HMI in
gps.r800.so. Alternative valid donor layouts require review, not guessing.
It checks literal properties and init/VINTF evidence, not effective runtime
property precedence or libvintf merging. Missing dependencies and linker
namespace rules need the existing Android linker audit as a separate gate.

SELinux: use original enforcing policy; inspect vendor_file_contexts,
hwservice_contexts and compiled policy for the actual GNSS service and
/oem/r800dev/gps.sock. The Tizen path /opt/usr/r800dev/gps.sock must map
to the same socket inode. No permissive policy, broad allow rule, chmod
change or automatic daemon launch is introduced by this audit.

Runtime acceptance (not executed): effective ro.hardware.gps/ro.hardware,
init service state, lshal IGnss/default, socket identity and access under
enforcing SELinux, and a synthetic location callback before outdoor fix.
Original donor image and its compiled SELinux policy remain unavailable.
safe_to_flash=false.
