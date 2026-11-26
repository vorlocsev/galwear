# Conditional location account DAC candidates

Baseline fe5531414292fa57152e83d17eeffcac994004fe: seven workflows
passed; GPS host job 139799390149, run 45787935307 confirmed
14 binary ACL/capability tests and actual ext4 binary roundtrip.

Model nonroot location UID and primary GID from the matched
configuration files only. Evaluate owner, named user, matching
group(s), mask, and other precedence; mode fallback remains
conditional because absent xattr listings do not prove absence.
Check each individual read/execute bit and directory search on
canonical audited paths. No combined-access assertion, alias
traversal, supplementary group, effective process UID, privilege
bypass, runtime mount or SELinux verification. Current launch
script does not explicitly select location UID; the model is not
a claim of actual lhd/gpsd/gpsbridge identities. gpsbridge resides
in external payload and is not tested by donor image audit.
Nine new tests and extended real ACL fixture pending CI.
No privileges restored, no hardware or original donor.
safe_to_flash=false.
