# Audited static tzlite staging

Baseline e1bdc5e64ed061bff9880d426822831b7c222af9: 7/7 workflows.
GPS host job 139770647556, run 45779318618: nine tzlite audit tests.

Use as non-root on Linux:
python3 src/tools/tzlite/mktzlite.py --static-candidate --root DONOR --output NEW_DIR
or python3 build/r800_stage_tzlite.py --root DONOR --output NEW_DIR.

Audit known components, copy only hash-bound ELF closure and four GNSS
configuration files, recreate relative library aliases, re-audit output
and source. Publish using Linux renameat2 RENAME_NOREPLACE only after
validation; failure leaves no candidate output. No special modes,
ownership or arbitrary recursive trees copied. Configuration modes are
private. Eleven fixture tests pending CI. Audit mocked in these tests;
real ELF audit covered separately. This is not a runnable tzlite rootfs:
other configs, plugins, directory aliases, ownership and runtime behavior
remain unverified. Legacy positional root-only copier remains unchanged
and is not an acceptance path. No original Tizen donor supplied.
safe_to_flash=false.
