# QEMU probe log validation: host evidence

Source HEAD: 783a8d5a34aab96e8e4e513546ecd26606217f28.
Two files were copied into an isolated local fixture and checked with
git hash-object against the GitHub content API:

- 608b43b474dc10a43f98e8c81815a9dded34914d build/r800_qemu_probe_log.py
- 2d365d82ed2d4b6b1d9cb44bc97490fc420a0a6c tests/test_r800_qemu_probe_log.py

Actual execution: PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
Result: 6 tests, OK. CLI also accepted a valid synthetic log and rejected
the same log after an additional PTHREAD_TLS=FAIL marker. Both exit checks passed.

This is host-only log validation, not QEMU or donor execution. The local
environment did not expose qemu-arm-static or bwrap via command -v;
github.com did not resolve via getent hosts. Full checkout, donor link,
Android runtime and exact-head CI are not verified here.

The previous integrated unit evidence document was not independently rerun
in this session; do not aggregate its numbers as new executed tests.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
