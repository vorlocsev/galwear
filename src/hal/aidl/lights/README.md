# R800 Lights AIDL adapter (development only)

The original Pixel Android 11 Vendor targets FCM 5. The level-5 framework
matrix declares android.hardware.light / ILights / default (AIDL, optional).
The existing R800 vendor recipe instead uses the Samsung-specific HIDL light
service from J4. Do not equate that service with the standard AIDL contract.

This candidate exposes only the panel backlight, ID 1, through the existing
lights.r800.so implementation. It loads the explicit ARM32 vendor library,
validates HMI and opens the backlight device before registering ILights/default.
Unsupported IDs return EX_UNSUPPORTED_OPERATION. Flash and alternate brightness
modes are best-effort; the existing HAL remains responsible for RGB luminance,
sysfs writes and retry behavior. No donor firmware or Pixel device-specific
light service is required by this source.

## Build and acceptance gates

1. Place the adapter directory in a disposable, pinned Android 11 AOSP platform
   checkout, then select an ARM32-capable product and run
   `m android.hardware.lights-service.galwear-r800`. The Soong target uses the
   Android 11-era version-1 NDK platform AIDL library naming; verify the exact
   selected platform exports that target. Do not substitute newer AIDL headers.
2. Inspect the resulting ARM ELF, DT_NEEDED closure, and generated interface
   version/hash against the intended donor. NDK-only HAL smoke build is not
   sufficient to compile the generated stable AIDL bindings.
3. Validate an explicit R800 VINTF fragment, init service and enforcing SELinux
   policy, including only the required backlight sysfs access. No permissive
   policy, guessed labels or duplicate Samsung/standard light registrations.
4. In a disposable Binder-capable guest, register the service, enumerate exactly
   one backlight, verify invalid IDs, compare RGB cases and retry on simulated
   sysfs failure. Then perform the appropriate physical-device acceptance
   separately and only with explicit authorization.

The existing synthetic Lights fixture passed on original Pixel Bionic at
4022d3918f353bbf77728a6a46d64700f5cb9eaf, run 46159060544. That tests the
legacy HAL only, not this AIDL adapter.

No product package entry, init_rc, VINTF auto-install, or vendor recipe change
is included. Platform build, Binder registration, SELinux, and hardware are
all unverified. safe_to_flash=false.

AOSP interface references:
- https://android.googlesource.com/platform/hardware/interfaces/+/5e4453f690dc15e30d43adc58fbc564e759ca475/light/aidl/android/hardware/light/ILights.aidl
- https://android.googlesource.com/platform/hardware/interfaces/+/1674c1354e4c191b9da955cd91f028abee359ae
