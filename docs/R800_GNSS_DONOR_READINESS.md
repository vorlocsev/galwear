# Static donor link integration

Baseline b7ad290eb975aec423df6796e9dc3d1fa250d7da passed 7/7
workflows; GPS CI 45772346857 confirmed 13/13 CI metadata tests.

    python3 build/r800_gnss_readiness.py \
      --tizen-image /path/rootfs.img --tizen-image-sha256 EXPECTED_SHA256 \
      --donor-ndk /path/android-ndk-r27c --donor-output /path/new-evidence

Runs static donor extraction/link in a fresh directory outside the checkout.
Binds the freshly generated report to source SHA, image SHA, all four
donor digests and saved linker log. No QEMU or donor binary execution
requested by this readiness option. A successful static check cannot
satisfy donor_glibc_qemu or hardware runtime. Ten synthetic evidence
tests pending exact-head CI. Original donor image absent.
safe_to_flash=false.
