# Static tzlite tree integrity manifest

Baseline 103fa2f15c9053a89e9ee6ba0e4209bc1c6e0612: all seven
workflows passed. Host job 139776098081, run 45780987908: five
actual compiled ARM32 ELF staging tests passed.

Static staging schema v2 records all candidate entries (except
the manifest itself), root and directory modes, file sizes/modes
and SHA-256, and literal relative symlink targets. Reject special
files, hardlinked files, escaping/dangling links and oversized trees.
Verify the manifest and inventory before atomic publication.
Keep the manifest SHA-256 separately in a trusted record:
  sha256sum NEW_DIR/tzlite-static-evidence.json
  python3 build/r800_tzlite_manifest.py --root NEW_DIR --sha256 DIGEST

The external digest is required, not inferred from a potentially
modified candidate. This is integrity evidence, not authenticity
or a signature. Use only stable isolated trees; path traversal
checks do not defend against a concurrent privileged adversary.
Twelve filesystem tests plus real compiled ELF roundtrip integration
pending CI. v1 manifests require rebuilding. No donor or device
test. safe_to_flash=false.
