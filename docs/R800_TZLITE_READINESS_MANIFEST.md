# Static tzlite manifest readiness gate

Baseline 0d120cbaa8caf8db8b8a3008fd56696cacd41dde: seven successful
workflows. GPS host job 139777713598, run 45781470394 confirmed all
12 manifest tests and the compiled ARM32 staging roundtrip.

Use --tzlite-root DIR --tzlite-manifest-sha256 DIGEST with
build/r800_gnss_readiness.py. Supply a separately trusted digest of
the v2 manifest, not one calculated from an untrusted current tree.
The integrity gate checks the external digest, exact schema/status,
positive counts and explicit false runtime/authenticity markers.
Recheck after component and other audits, with identical report
evidence required. Missing digest remains NOT_TESTED. This gate
does not replace the known component audit or authenticate donors.
Eight additional tests, including real verifier subprocess and
mutation between checks, pending exact-head CI. Stable isolated
offline tree required; transient modifications can escape scans.
Original Tizen and hardware still untested. HOLD_RUNTIME_UNVERIFIED.
safe_to_flash=false.
