# SM-R800 PIT geometry validation — research branch

This branch builds on `hardening/r800-netodin-protocol-20261124` and runs exclusively in `vorlocsev/galwear`. It does **not** alter `main`, create pull requests, or contact/watch-flash hardware.

## New prewrite gate

After reading and validating the *live* PIT, but before the first Odin CMD_FILE_TRANSFER (102), the installer:

1. Parses the 132-byte Samsung PIT entries and reads the block offset and block count.
2. Rejects missing or zero block counts, unknown device types, overflowing ranges, or missing expected R800 entries.
3. Assumes an eMMC logical sector is **512 bytes** and computes `block_count * 512` for each expected image.
4. Rounds each TAR member's logical byte length up to the next 128-KiB transport block for a conservative upper bound.
5. Rejects the entire update before any block transfers if **any** padded image exceeds its assumed capacity.

The final comparison is a safety heuristic, **not** proof the PIT fields are eMMC sectors for every device/partition type. The interpretation comes from public Samsung PIT descriptions and this project's known p17 USER size (1,918,369,792 bytes = 3,746,816 * 512). A validated live R800 PIT dump and real archive metadata are required before regarding this check as device-correct.

**A passing result is NOT flashing permission.** Image authenticity, retail vs engineering S-Boot, rollback, recovery, real PIT framing, actual storage layout, and USB recovery are unverified. Incorrect geometry assumptions should cause a false positive abort rather than allowing an uncertain write.

## CI

GitHub Actions run only synthetic tests. The mock watch is a minimal Python byte-stream simulator, not a Samsung bootloader. Existing installer, transfer-error, and recovery test suites run as regressions.

## No release

No Wear OS firmware is built or distributed by this branch. No actual device is accessed.
