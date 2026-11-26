# Local donor glibc acceptance

Baseline f133c531d0993fa8a9bb687d1debb82aef1a7c72:
7/7 workflows succeeded; GPS run 45769341341 confirmed 19/19
native, ARM QEMU and freestanding ARM QEMU tests. No original
Tizen glibc or Broadcom library was supplied.

Use a clean checkout, unprivileged Linux, pinned NDK r27c, e2fsprogs,
and a trusted raw Tizen ext4 rootfs with independently known SHA256.

    python3 build/r800_gps_donor_check.py --image /path/rootfs.img \
      --sha256 EXPECTED_SHA256 --ndk /path/android-ndk-r27c \
      --output /path/new-evidence

The output must be outside the checkout and not exist. Optional
--run-qemu explicitly runs only trusted donor glibc using the existing
bubblewrap/QEMU isolation. The report binds the image, individual
donor bytes, clean source SHA, static closure and log hashes.
Extracted donor binaries and compiled bridge are scratch-only.
No proprietary Broadcom execution; no device or flash authorization.
The report does not authenticate the origin of the provided image.
New synthetic evidence tests pending CI. Real donor input absent.
safe_to_flash=false.
