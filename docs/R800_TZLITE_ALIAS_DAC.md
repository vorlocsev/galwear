# Conditional DAC over image resolver traversal traces

Baseline 96177d17f2e4a1798b105d86dce9e19dc6192b9d: seven workflows
passed. Host job 139801947206, run 45788698735: nine DAC tests
and actual named ACL fixture passed.

Record successful bounded guest ELF path traversals, including
all visited directories (even ones popped by ..) and symlink
components. Collect original metadata for traversed directories.
Evaluate individual read bits and execute bits on programs and
PT_INTERP aliases, plus search bits on each traversed directory,
for the same conditional location identity. A missing or
mismatched trace is review-required. No runtime alias access
verified; no supplementary groups, symlink protection settings,
capability bypass, mount policy or SELinux checks. Results refer
to original image, not staged ownership. Two new DAC unit tests
and one actual ext4 detour test pending CI; existing loader
fixture strengthened. No original donor or hardware.
safe_to_flash=false.
