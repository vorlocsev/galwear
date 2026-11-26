# Donor pipeline validation

Baseline abf670fd17391b4cca50a8e7a15e445d1633a02a passed seven
workflows. GPS run 45769939240 host job 139739885988 reported all
nine donor evidence tests passing. Native and both synthetic QEMU
modes passed 19 integration tests each.

New checks require per-library runtime snapshot hashes and ordered
probe markers to agree with the extracted image evidence. Explicit
gate state distinguishes extraction, ELF, link and QEMU failures
from untested steps. Added ten orchestration tests: three real ext4
negative scenarios and seven simulated link/QEMU scenarios with real
ext4 extraction and report checks. No donor code is executed by these
tests. Exact-head CI pending. Original Tizen image absent.
safe_to_flash=false.
