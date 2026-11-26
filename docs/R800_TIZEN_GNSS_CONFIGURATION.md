# Tizen GNSS configuration prerequisites

Baseline ef833b0750315ff9aff12e893e1f16d78fc6f2b2: all seven workflows
passed. Host job 139766755172 in run 45778143688 confirmed all eleven
mount helper tests.

Extend prepared-root GNSS preflight with bounded regular configuration
files, SHA-256 of lhd.conf, gpsd.xml, passwd and group; XML syntax
only (DTD/entity declarations require review), unique non-root location
account and explicit location group candidates. Reject symlinked
configuration paths conservatively; do not read location caches or
emit configuration contents. No claims about effective NSS identity,
daemon configuration semantics or vendor compatibility.

Require nonempty regular lhd configuration before chroot-ready,
and gpsd executable, library presence and nonempty nonsymlinked gpsd.xml
before launching GPS workers. These device checks are existence
heuristics, not guest ELF or effective permission checks. Original
donor may use legitimate symlinks requiring further review.
Seven additional static cases and one restart-loop case pending CI.
No changes to firmware or policy. safe_to_flash=false.
