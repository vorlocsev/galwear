# Real ARM32 ELF integration fixture

Baseline c6d6f06c6574257f730a9a1b420406c89322ef64: seven workflows
successful. GPS host job 139773601214, run 45780225050, confirmed
11 static staging fixture tests.

Add five mandatory integration cases using clang/lld to compile
actual synthetic ARM32 soft-float binaries, shared plugins, provider
and a nonfunctional loader ELF. Programs contain PT_INTERP and
DT_NEEDED; the provider is reached through guest directory and file
aliases. Exercise actual audit and atomic staging without mocking
the audit, compare staged hashes, reject missing provider/plugin and
wrong machine. Require an unprivileged Linux runner. No ARM code
is executed; the synthetic loader is not glibc and the libraries
are not original Tizen components. No chroot or hardware test.
CI pending. safe_to_flash=false.
