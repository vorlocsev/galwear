# Non-executable metadata review plan

Baseline 48d9b42ed6d43c0d2980e614b07a6ff1193c3f0d: 7/7 workflows
passed; GPS host job 139807383310, run 45790322118 confirmed
seven metadata comparison tests and special-mode ext4 case.

The image binding report now includes metadata_review_plan,
bound to both external digests and deterministic hashes of
the metadata evidence and comparison. Any content mismatch
blocks the plan and yields zero review items. Otherwise
categorize ownership, mode, xattrs, privilege, writable
paths, path layout, access, scope, runtime mounts and external
payload reviews. Even identical special rights or equal
denied access require review. All entries REVIEW_ONLY.
No command generation or execution, no owner/permission
restoration authorization, no claim of complete original
inventory. Eight unit tests and strengthened real ext4 cases
pending CI. No original donor or physical device.
safe_to_flash=false.
