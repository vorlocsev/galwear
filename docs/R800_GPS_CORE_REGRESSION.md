# GPS core regression evidence

Baseline HEAD: 6ff2d3cf4a05c7d9e228c820494b2cc61477a0ae.
Local run on 2026-11-25, native Linux x86-64, GCC 14.2.0, Clang 17.0.0.
The 18 source and test files listed below were checked against exact Git blobs
fetched at that HEAD. No complete checkout was available (DNS failure).

```sh
sh build/r800_gps_core_checks.sh
```

Actual result: 7 C executables PASS under UBSan, 8 Python aggregator tests
PASS, 3 ARM32 ABI compile probes PASS, 3 invalid ABI rejection checks PASS.
No errors observed in this subset. This does NOT compile the complete bridge,
Android HAL, or execute the two-sided integration fixture. No target link,
donor, QEMU, CI or physical result is claimed.

Exact tested inputs (Git blob SHA-1):

```text
0bb55b2a24d21739e697a1d59bb873f2f527d8e5 build/r800_gnss_readiness.py
f711862b4986b0d2daf540296b73c6d0430d2ee3 src/hal/gps_nmea.h
c04b2512e1c14c02096f208f0b2d8d456f866e9d src/hal/gps_wire.h
041577e8a758c9fbcfc54da37b3f791d20a333be src/tools/gps/gps_command.h
cb3ca4134fae88657b8b9181b821d74583dbc59c src/tools/gps/gps_frame.h
d9d68c4f12e5a7690fccfadd8bd17118f3079156 src/tools/gps/gps_ipc.h
cc546d1646acc7b310415d25c911b0deba348064 src/tools/gps/gps_lto.h
da3a067d88136f48de76c9a632e2706f8e1b62b9 src/tools/gps/gps_output.h
4fd5f7d01e942711549daa23d8cd63995f549dda src/tools/gps/gps_abi.h
dc4c2e487685300db22689d63a0ee2d102a2d142 tests/r800_gps_abi_probe.c
58015a41124d61179ad7186a9e5dc2601fd55d7e tests/test_r800_gnss_readiness.py
f0808f0c63aeb0701097efff270bd46848b2591d tests/test_r800_gps_command.c
9a028008064676e8de86c2b2a8f9054fa7e700a4 tests/test_r800_gps_frame.c
e2988d7e1a7d66074f95a0da4d4f3bb73e39b3a0 tests/test_r800_gps_ipc.c
199b11245b7dd82f0f414a179ca87d5bbbc99c22 tests/test_r800_gps_lto.c
cc9a27efd02e397981d3d14d08163af5852c22dc tests/test_r800_gps_nmea.c
64a0d03e67368375280d19a47072d180b0917a06 tests/test_r800_gps_output.c
507deca8d66527f65463139f83cd7447dbb9351b tests/test_r800_gps_wire.c
224dce2842b1f883b902a3516e79aa9c122c9ee4 build/r800_gps_core_checks.sh
```

The core script emits GPS_CORE_CHECKS=PASS only after these checks succeed.
It intentionally does not emit the full offline gate success marker.
safe_to_flash=false.
