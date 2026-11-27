# GalWearOS — Wear OS 3.5 for Samsung Galaxy Watch SM-R800

**Experimental integration branch. NON-RELEASE. safe_to_flash=false.**

Target: Samsung Galaxy Watch 46 mm Bluetooth (SM-R800), Exynos 9110,
Linux 4.19 and Wear OS 3.5 / Android 11. The historical prototype uses
Pixel Watch system image RWDC.230905.003. Its reported hardware features
are not acceptance evidence for this integration branch.

## Development status

See [ROADMAP.md](ROADMAP.md) for exact-commit CI evidence, remaining
dependencies and release gates.

- [Component build instructions (RU)](docs/R800_COMPONENT_BUILD_RU.md)
- [Local donor inventory (RU)](docs/R800_DONOR_SOURCES_RU.md)
- [GNSS acceptance contract](build/README.r800-gps-acceptance.md)
- [Recovery and provenance requirements (RU)](docs/R800_STAGE10_PROVENANCE_RU.md)

The local kernel build uses a read-only diagnostic initramfs with storage
isolation. Android handover is a separate experimental implementation,
not a verified boot path. Do not equate successful compilation with a
working Wear OS installation.

## Installation status: HOLD

No installation or update is approved for this integration branch.
Retail S-Boot compatibility, authentic PIT geometry and independent
hardware recovery remain unverified. NetOdin simulations do not prove
that real hardware can be safely flashed or recovered.

The historical README is preserved in [738e3d8](https://github.com/vorlocsev/galwear/blob/738e3d8f52da481d82857fc65705c3fd363b4eb8/README.md)
for reference only. Its installation and root-telnet instructions do not
apply to the current integration branch. Do not use them to install this build.

CI publishes evidence, not firmware packages. Keep donor images and
personal device data outside Git.

## Credits and licenses

- The code in this repository is under the MIT license in `LICENSE`, with these
  exceptions:
  - `src/kernel/r800-wearos.patch` is under GPL-2.0, like the kernel.
  - `src/hal/include` holds Android headers under Apache-2.0.
  - `installer/netodin.py` comes from
    [prakashdivyy/py-netodin](https://github.com/prakashdivyy/py-netodin), with a
    reboot-only mode added. Its own terms apply.
- The release package contains Google's Wear OS images and apps and Samsung's
  firmware. They belong to their owners.
