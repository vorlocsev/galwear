# SM-R800 NetOdin: fail-closed transfer hardening

**Fork-only experimental branch**: `hardening/r800-netodin-protocol-20261124`. Based on `hardening/r800-recovery-audit-20261124`.

## Fixes

- Reject short/empty reads from firmware images before sending padded blocks or committing the corresponding transfer window. The former `if not chunk: break` could leave the outer loop repeating with zero progress.
- For CMD_FILE_TRANSFER (102), reject any nonzero ACK status at window-start, window-size, chunk and eMMC-commit stages. Version-like nonzero status values in CMD_SETUP (100) are deliberately unchanged.
- Keep the existing strict *live* PIT validation gate before any CMD_FILE_TRANSFER.
- Preserve the existing PIT last-chunk framing until real protocol captures are available; there is no evidence yet that alternate framing is correct.
- Add a deterministic mock socket/watch to confirm that malformed/missing PIT triggers no data-phase calls, and that write-phase errors stop the transfer.

## Limits

**Only synthetic software simulations and GitHub Actions CI.** The fake watch in tests is not an SM-R800 hardware emulator and its ACK conventions may differ from retail or engineering bootloaders. A nonzero ACK may be valid for some device variants; this code intentionally fails closed if uncertain.

No released Wear OS image or Samsung combination image was tested on a real watch. No successful flash, read-back, retail S-Boot compatibility, stable Wireless Download, or wired recovery can be inferred.

## Run

```sh
python3 -m unittest discover -s tests -p 'test_netodin_protocol.py' -v
```

Do not perform live flashing based solely on these tests.
