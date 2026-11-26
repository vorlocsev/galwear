# GNSS binary policy readiness integration

Baseline b876eb76ad6767dc9674f5882987fb778967a29b: 7/7 workflows.
GNSS host job 139757223291, run 45775247976: secilc 3.5-1,
setools 4.4.4-1build1, seven real compiled synthetic policy tests passed.

The readiness report accepts --android-root ROOT --selinux-policy
GUEST_PATH --selinux-policy-sha256 SHA256 --selinux-types TYPES.json.
GUEST_PATH is /sepolicy or vendor/odm precompiled_sepolicy at the
standard SELinux directory. Require static Android registration pass;
choose the AOSP/Samsung candidate from the report, compare exact
hwservice label types, bind SHA, profile and explicit types to the
fresh policy audit, and reject runtime claims. The selected policy
is only a file from the prepared Android tree, not proof that init
would select or load it. Remaining type labels are explicit candidates,
not effective labels. Eleven new tests pending CI. No policy loading
or modification. selinux_enforcing_access remains NOT_TESTED.
safe_to_flash=false.
