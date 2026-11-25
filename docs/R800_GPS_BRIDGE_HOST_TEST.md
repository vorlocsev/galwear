## Real-source host integration

`python3 -m unittest discover -s tests -p 'test_r800_gps_bridge_integration.py' -v`

Compiles the actual bridge and Android reader on native Linux with UBSan; a synthetic shared library supplies Broadcom callbacks. Tests normal START/STOP, TIME/LOC and failure of re-init or STOP. All files and socket are in disposable temporary directories. No donor code, device access, flash or ARM ABI validation. Host mode is explicitly compiled, not a release target. safe_to_flash=false.
