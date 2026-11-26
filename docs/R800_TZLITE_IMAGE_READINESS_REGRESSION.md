# Exact-head readiness regression

5990dd36f8b1a04a6749b71b59fdbe46e646a051: 4/7 workflows passed.
GPS host run 45784144644, job 139786563706 failed in
test_cli_routes_and_revokes: KeyError 'detail'. The mock static
gate omitted the detail dictionary required by tzlite_image_gate.
The actual compiled ELF/ext4 image readiness subprocess test
passed in that same job. Android HAL and ARM QEMU jobs passed.

Correct the mock to return a complete synthetic report. Reject
absent/non-dictionary detail in both tzlite gates, and require a
valid report digest on final integrity recheck. Add three negative
tests. No relaxation of status, count, hash or safety checks.
This commit is a targeted regression fix; exact-head CI pending.
Original ownership audit deferred until a green baseline.
No device or upstream changes. safe_to_flash=false.
