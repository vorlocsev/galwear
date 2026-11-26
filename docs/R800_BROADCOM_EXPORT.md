# Broadcom GPS export contract

Inspect the extracted libbrcm.so without loading or executing it:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 build/r800_broadcom_export.py --library /path/to/gnss-extracted/tizen/libbrcm.so
```

The audit conservatively requires one strong default-version-visible
STT_FUNC export named gps_get_hardware_interface, ARM32 EABI5 without
the hard-float flag, a dynamic shared object and a complete supported
symbol inventory. Unspecified symbol types, IFUNC, weak or ambiguous
exports require review rather than being accepted. It also reports
DT_NEEDED and the exact file SHA-256. The full Tizen GNSS preflight
reuses this gate; dependency closure still requires the complete
offline donor filesystem.

EXPORT_CANDIDATE does not establish a function signature, return
structure, callback convention or proprietary XTRA ABI. The current
local contract assumes GpsInterface=40, GpsCallbacks=40,
GpsLocation=56 and GpsXtraInterface=12 bytes for ARM32. These are
compile-time local layout assertions, not donor facts.
Keep R800_XTRA_ABI=0 until the specific donor ABI is verified.

## Executed verification

Ten unit tests ran successfully in an isolated two-file local fixture
with Python unittest, no skips. git hash-object matched:
- 9f50a8b2ca085f57b2c6e530feda62d4d08ca68f build/r800_broadcom_export.py
- 56315cae6dc05f965300b52983703b2fc908454e tests/test_r800_broadcom_export.py

Synthetic metadata only; the CLI real ELF parser and integrated
preflight were not executed. No original Broadcom library or actual
device was examined. No exact-head CI claim.
HOLD_RUNTIME_UNVERIFIED; safe_to_flash=false.
