# Offline GNSS allow candidates

Baseline 3858034658e6c02dd8542bce891c0359e6ed0cdf: 7/7 workflows.
GPS host job 139753235318 in run 45774034210 confirmed 17 IPC tests.

New static tool: python3 build/r800_gnss_policy.py --policy POLICY
--sha256 EXPECTED_SHA256 --types TYPES.json [--samsung].
Supply explicit candidate names: hal_domain, bridge_domain, oem_dir_type,
ipc_dir_type, socket_type, gnss_hwservice_type (and sec_hwservice_type
for Samsung). No guessed labels. Requires trusted installed SETools.
Queries concrete type candidates and necessary unconditional allow rules
for directory traversal, socket access, peer connectto and registration.
Conditional rules alone do not pass. No policy loading or modification.
Attribute matching is delegated to sesearch; actual label selection,
constraints, MLS, transitions, kernel policy and runtime enforcing remain
unverified. Ten synthetic mocked-tool tests pending CI; real SETools
and original binary policy not tested in this change.
safe_to_flash=false.
