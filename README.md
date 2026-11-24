# Wear OS 3.5 for the Galaxy Watch SM-R800

> **Galwear experimental development branch — read before installation.** The
> historical installation instructions below describe an earlier prototype;
> they are not validated on a retail SM-R800. The hardened NetOdin on this
> branch intentionally refuses live flashing without separate reference
> verification. Do **not** attempt an installation based on green GitHub Actions:
> all tests are synthetic. First use the read-only `--preflight-only` mode and
> see `docs/R800_STAGE10_PROVENANCE_RU.md`. Neither a proven wired recovery
> path nor retail S-Boot compatibility is established.


This project runs Wear OS 3.5 on the Samsung Galaxy Watch 46 mm Bluetooth, model
SM-R800. Wear OS 3.5 here is Android 11, from the Pixel Watch system image
`RWDC.230905.003`. A custom Linux 4.19 kernel runs it. Tizen is removed, and
Samsung's bootloader stays.

It works only on the SM-R800. It was developed and tested on one watch.

## What works

- Display, touch, both buttons and the rotating bezel
- Always-on display
- Wi-Fi and Bluetooth, with the watch's own factory addresses
- Pairing with a phone through the Wear OS app, and internet through the phone
- Play Store, Google apps and notifications
- Gemini, by voice with "Hey Google" or by double-pressing the bottom button
- Speaker and microphone
- Heart rate, steps, accelerometer, gyroscope, barometer and light sensor
- GPS
- Wireless charging on Samsung's charger, with a charging screen when the watch is off
- Flashing updates over Wi-Fi

Deep sleep partially works.

## Buttons

| Button | Press | Double press | Hold |
|---|---|---|---|
| Top | Back, or screen off on the watch face | | |
| Bottom | Home and app list | Gemini | Power menu |

## Before you flash

- The install replaces all of Tizen and writes Samsung's factory bootloader, from
  the combination firmware. To go back to Tizen, flash stock firmware with Odin.
- The install does not touch the watch's factory data, which holds its Bluetooth
  and Wi-Fi addresses and its calibration.
- Never flash `cm.bin` from any firmware package. It is tied to the watch's secure
  storage.

## Install

You need these:

- the watch, charged above 50 %
- a PC with Wi-Fi and Python 3
- this repository, for `installer/netodin.py`
- `R800-WearOS.zip` from the [releases page](../../releases), unzipped to
  `R800-WearOS.tar.md5`

Steps:

1. Put the watch in Download Wireless mode. Hold the bottom button for about 10
   seconds, until the **Select REBOOT MODE** menu appears. Short-press the button
   to move to **Download (Wireless)**, then long-press it to select.
2. The watch starts in WPS mode. Double-press the bottom button to switch to AP
   mode. The watch now broadcasts an open Wi-Fi network named `SM-R800-xxxx`.
3. On the PC, start the flasher:

   ```
   python3 installer/netodin.py --ap R800-WearOS.tar.md5
   ```

4. Connect the PC to the watch's network. The watch connects to the flasher, checks
   the package, flashes it and restarts. The PC has no internet while it is on the
   watch's network.
5. The first boot takes a minute or two. Follow the setup screen on the watch, and
   pair it with the Wear OS app on your phone.

Nobody has tested the install on a watch that still has Samsung's retail
bootloader. If the flash stops with an error after the bootloader step, put the
watch back in Download Wireless mode and run the same command again.

## Updating

On Wear OS, run `reboot wdownload`, or use the button menu from the install steps.
The watch shows a "Wireless download" screen. Double-press the bottom button to
start an open network named `SM-R800`, then flash with `netodin.py` as in the
install steps. To cancel, hold the bottom button for 3 seconds. The watch then
restarts into Wear OS.

## Developer mode

An empty file at `/oem/r800dev/android/DEV` turns on developer mode. It adds a root
telnet shell over Wi-Fi, keeps logs on the watch and skips the setup screen. To use
it, add the file to the payload before you build a package. The release has it off.

## Building

The scripts are in `build/`. The kernel patch, kernel config, device tree, HALs and
tools are in `src/`. Google's and Samsung's images go in `images/`, which git
ignores.

1. Kernel: apply `src/kernel/r800-wearos.patch` to the AOSP Exynos 9110 4.19
   kernel and build it with `src/kernel/r800.config`. Pack it with
   `build/mkboot.sh` and `src/dt/r800.dts`.
2. Payload: run `build/mkpayload-release.sh`.
3. Package: run `build/mkrelease.sh`. It needs Samsung's combination firmware
   `COMBINATION-FT40_R800XXU1ARI2`.

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
