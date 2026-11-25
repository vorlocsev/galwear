# GPS binary ELF gate evidence

Source: f1f5d8c7a576691177e293f796242fd94b13035e.

The shared Android relocation parser initializes packed_tags but does not
populate it. The GPS-specific gate now explicitly rejects Android APS2
dynamic tags as well as standard and Android RELR tags for both executables
and DSOs, independent of that inventory field.

Actual local execution on Python 3.13.5:
- git hash-object for build/r800_gps_link_gate.py matched
  8f26eb0dc1908025216d6f3973769b1cbe745a34.
- tests/test_r800_gps_link_gate.py matched
  2f1586f9fc747cf401d48b78cc056e997775c658.
- 17/17 symbol tests passed using stub external imports.
- 10/10 prohibited dynamic tag cases rejected, and a DT_NULL control
  accepted, using synthetic byte buffers with a stub inspect result.
  This specifically tests the independent raw-tag scan, not the full parser.

The new tests/test_r800_gps_binary_elf.py contains 11 test methods, including
eight packed encoding/executable combinations in one method. It imports
the actual Android ELF parser and existing fixture helpers. It is wired
into the full offline gate. These new real-parser tests have NOT been run:
the complete checkout and its imported inventory modules are unavailable
locally. GitHub DNS resolution remains unavailable in the local environment.

No target link, QEMU, CI, donor execution or hardware test is claimed.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
