# GPS ELF symbol binding regression evidence

Source commit: ffff8349e4e6f4e2c67920f575ec25072084cdaf.
On 2026-11-25, two files were reconstructed from the GitHub content API
in a local isolated fixture and both git hash-object results matched:

- a2498fcba65aa3de56583ee9bee1fb507b1c6891 build/r800_gps_link_gate.py
- 2f1586f9fc747cf401d48b78cc056e997775c658 tests/test_r800_gps_link_gate.py

Python 3.13.5: unittest discovery ran 17 tests, all passed, no skips.
The three imported external modules (Android ELF parser, regular-file
reader and Tizen interpreter parser) were replaced in sys.modules with
stubs that raise AssertionError if called. This intentionally verifies
only check_version/import_problems and symbol matching, not ELF parsing,
relocation parsing, the full audit function or actual donor linking.
The new packed-relocation rejection code was reviewed but not executed.

Environment checks: command -v qemu-arm-static and command -v bwrap
returned no paths; getent hosts github.com returned no addresses.
No original donor libraries, QEMU, full checkout or CI were verified.
Earlier evidence reports were not independently rerun.

Next: add ELF fixture tests for packed relocations and malformed headers,
then test with actual resolved Tizen glibc 2.24 files.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
