# GNSS IPC identity preflight

Run on two distinct, already prepared offline roots, not on live Android:

```sh
python3 build/r800_gnss_ipc_layout.py --android-root /path/to/android --tizen-root /path/to/tizen
```

Reads only init metadata, partition passwd/group files, directory metadata and
SELinux context evidence. No mounts, chown, chmod, service launch or socket
connection. Symbolic account names must have a unique explicit database entry;
compiled-in Android AIDs not present in those files require separate evidence.
Numeric values must be non-root. The primary GID is a candidate, not necessarily
the correct sharing group. The target directory and its ancestors must be
root-owned and not group/world-writable. Separate extracted directories cannot
prove the shared bind mount; only matching device and inode in a prepared
snapshot are accepted. Existing socket/marker paths require a separate review.

Context file hashes and literal GNSS/path mentions do not prove SELinux access.
Before enabling the bridge, verify effective service UID, groups, actual socket
identity and enforcing policy on a controlled target. No build credentials
are automatically emitted. safe_to_flash=false.
