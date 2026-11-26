# Static NSS provider review

Baseline 57b45d9b8b5057f6a19c5c7a3eedc1934e547f31: 7/7 workflows;
GPS host run 45800752092 job 139843036704 confirmed nine config
parser tests and actual ext4 config case.

Opt-in --review-nss implies config review and plugin audit, on
same snapshot. Map basic passwd/group/hosts databases to files
and dns candidates, preserve provider order. Review additional
databases and DNS outside hosts. Require unique provider across
the three static search directories, bind to audited closure
hash and exact SONAME, check strong nonhidden function exports
for selected basic lookups. Require relevant hosts/resolv syntax.
No network access or dlopen, no actual libc lookup order, account
or complete NSS ABI claim. Missing exports in synthetic fixture
are review, not proof of deployed failure. Separate report digest;
no changes to extended manifest or staging. Seven unit tests and
two actual ARM ELF/ext4 cases pending CI. Original donor absent.
safe_to_flash=false.
