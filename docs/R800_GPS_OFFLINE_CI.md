# GPS offline CI

The offline gate uses native C tests with UBSan, Python synthetic ELF and
EXT4 fixture tests, and freestanding ARM32 compilation of the actual bridge
for all three XTRA modes. Hard-float, ARM64 and unknown XTRA mode are rejected.
No donor downloads, no flashing, no ARM code execution, no release artifacts.
Ubuntu host package versions are not pinned: compiler versions are logged.
The workflow runs only on its named fork development branch or by manual
dispatch where GitHub permits it. A successful job is evidence only for
its exact checked-out commit. Runtime glibc and GNSS gates remain separate.

Local equivalent: sh build/r800_gps_offline_checks.sh

safe_to_flash=false
