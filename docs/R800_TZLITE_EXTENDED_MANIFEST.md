# Extended component manifest

Baseline 60376e1d8ba5fff36507342ede231fe095e4c246: 7/7 workflows.
Host job 139821465439 in run 45794467987 confirmed all three
extra plugin ELF cases and offline compile gate.

Pass --extended-manifest to the legacy image scope CLI. It
implies --audit-plugins, uses the same snapshot, and binds the
review-only manifest to the image digest and deterministic
hashes of inventory and plugin audit evidence. Separate
AUDITED_ELF, KNOWN_CONFIG and UNREVIEWED_DATA; latter is
not a validated configuration. Unreviewed ELF outside closure,
missing paths and symlink/special-object issues remain review
items. Closure failure produces no component list. Check
overlap hashes, aliases, parent conflicts and aggregate budgets.
No staging authorization, metadata restoration or runtime
claim. Seven new unit tests and extended real ELF case pending
CI. Original donor unavailable. safe_to_flash=false.
