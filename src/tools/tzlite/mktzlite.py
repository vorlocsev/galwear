#!/usr/bin/env python3
"""
mktzlite.py: copy the part of the Tizen rootfs (p18) that the Wear OS build runs
in its chroot (lhd, gpsd, sensord, sensorctl, gpsbridge's libbrcm, plus the shell
tools the helper calls) into a small tree, following every DT_NEEDED and the
config files Tizen's daemons were seen opening (openlog.so trace, 2026-11-20).

  mktzlite.py <mounted Tizen rootfs> <out dir>

Run as root (keeps owners). p16 (/opt) and p17 (/opt/usr) are not part of it:
they stay mounted over the tree as before (tzchroot.sh).
"""
import os, shutil, stat, subprocess, sys

# The legacy full copier is not an acceptance gate. The explicitly
# selected static-candidate mode stages only audited known components.
if len(sys.argv)>1 and sys.argv[1]=="--static-candidate":
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).resolve().parents[3]/"build"))
    from r800_stage_tzlite import main
    sys.argv=[sys.argv[0],*sys.argv[2:]]
    raise SystemExit(main())

SRC, OUT = sys.argv[1].rstrip('/'), sys.argv[2].rstrip('/')

BINS = [
    '/usr/bin/lhd', '/usr/bin/gpsd', '/usr/bin/sensord', '/usr/bin/sensorctl',
    '/usr/bin/env', '/usr/bin/chown', '/usr/bin/bash', '/usr/bin/sh',
    '/usr/bin/ls', '/usr/bin/cat',
]
LIBS = [
    # dlopen()ed, so not in any DT_NEEDED
    '/usr/lib/libbrcm.so',                        # gpsbridge
    '/usr/lib/libnss_files.so.2', '/usr/lib/libnss_dns.so.2',
    '/usr/lib/gconv/gconv-modules.cache',
    # mapped by the running daemons (from /proc/*/maps)
    '/usr/lib/libSLP-tapi.so.0', '/usr/lib/libcontext-client.so.4',
    '/usr/lib/libcontext-sensor-recorder-client-genuine.so.4',
    '/usr/lib/libcontext-shared.so.4', '/usr/lib/libtracker.so.1',
    '/usr/lib/libwrappergps.so.0', '/usr/lib/libjson-glib-1.0.so.0',
    '/usr/lib/libgdbm.so.3', '/usr/lib/libunwind.so.8',
]
TREES = ['/usr/lib/sensor', '/etc/lhd', '/etc/gps-manager']
FILES = [
    '/etc/passwd', '/etc/group', '/etc/nsswitch.conf', '/etc/hosts',
    '/etc/ld.so.cache', '/etc/info.ini', '/etc/deviced/device/power.conf',
    '/etc/sensor_cal.conf', '/etc/system_info_db', '/usr/etc/sensor.xml',
    '/etc/tizen-platform.conf', '/etc/resolv.conf', '/usr/lib/charset.alias',
    '/etc/localtime',
]
# top-level symlinks and mount points (tzchroot.sh mounts dev proc sys tmp run opt mnt)
LINKS = ['/bin', '/lib', '/sbin', '/var', '/home', '/media']
DIRS = ['/dev', '/proc', '/sys', '/tmp', '/run', '/opt', '/mnt']

copied = set()


def real(p):
    """path inside SRC with symlinks (absolute ones relative to SRC) resolved"""
    parts, cur, seen = p.strip('/').split('/'), '', 0
    while parts:
        cur = cur + '/' + parts.pop(0)
        st = os.lstat(SRC + cur)
        if stat.S_ISLNK(st.st_mode):
            seen += 1
            if seen > 40:
                raise OSError('loop ' + p)
            t = os.readlink(SRC + cur)
            base = '' if t.startswith('/') else os.path.dirname(cur)
            parts = (base + '/' + t).strip('/').split('/') + parts
            cur = ''
            # normalise .. and .
            norm = []
            for x in parts:
                if x == '..':
                    if norm:
                        norm.pop()
                elif x not in ('', '.'):
                    norm.append(x)
            parts = norm
    return cur


def mkparents(p):
    d = os.path.dirname(p)
    if d and not os.path.isdir(OUT + d):
        mkparents(d)
        st = os.lstat(SRC + d)
        os.mkdir(OUT + d)
        os.chown(OUT + d, st.st_uid, st.st_gid)
        os.chmod(OUT + d, stat.S_IMODE(st.st_mode))


def copy(p):
    """copy p (and, for a symlink, its whole chain) keeping owner and mode"""
    if p in copied or not os.path.lexists(SRC + p):
        return
    copied.add(p)
    # parent directories may themselves be symlinks (e.g. /lib -> usr/lib)
    parent = os.path.dirname(p)
    if parent != '/' and real(parent) != parent:
        copy(real(parent) + '/' + os.path.basename(p))
        return
    mkparents(p)
    st = os.lstat(SRC + p)
    if stat.S_ISLNK(st.st_mode):
        t = os.readlink(SRC + p)
        if not os.path.lexists(OUT + p):
            os.symlink(t, OUT + p)
        os.lchown(OUT + p, st.st_uid, st.st_gid)
        tgt = t if t.startswith('/') else os.path.normpath(os.path.dirname(p) + '/' + t)
        # follow file links; a link to a directory (/bin -> usr/bin) is just kept
        if os.path.lexists(SRC + tgt) and not os.path.isdir(SRC + real(tgt)):
            copy(tgt)
    elif stat.S_ISDIR(st.st_mode):
        if not os.path.isdir(OUT + p):
            os.mkdir(OUT + p)
        os.chown(OUT + p, st.st_uid, st.st_gid)
        os.chmod(OUT + p, stat.S_IMODE(st.st_mode))
        for n in sorted(os.listdir(SRC + p)):
            copy(p + '/' + n)
    elif stat.S_ISREG(st.st_mode):
        shutil.copyfile(SRC + p, OUT + p)
        os.chown(OUT + p, st.st_uid, st.st_gid)
        os.chmod(OUT + p, stat.S_IMODE(st.st_mode))
        elf(p)


def needed(p):
    try:
        out = subprocess.run(['readelf', '-dW', SRC + p], capture_output=True, text=True).stdout
    except OSError:
        return []
    return [l.split('[')[1].split(']')[0] for l in out.splitlines() if '(NEEDED)' in l]


def elf(p):
    with open(SRC + p, 'rb') as f:
        if f.read(4) != b'\x7fELF':
            return
    for n in needed(p):
        for d in ('/usr/lib', '/usr/lib/sensor'):
            if os.path.lexists(SRC + d + '/' + n):
                copy(d + '/' + n)
                break
        else:
            print('unresolved', n, 'for', p)
    # the dynamic loader (PT_INTERP)
    out = subprocess.run(['readelf', '-lW', SRC + p], capture_output=True, text=True).stdout
    for l in out.splitlines():
        if 'Requesting program interpreter' in l:
            copy(l.split(': ')[1].rstrip(']'))


os.makedirs(OUT, exist_ok=True)
for l in LINKS:
    copy(l)
for d in DIRS:
    mkparents(d + '/x')
for p in BINS + LIBS + FILES + TREES:
    if os.path.lexists(SRC + p):
        copy(p)
    else:
        print('missing in rootfs:', p)
total = sum(os.lstat(os.path.join(r, f)).st_size for r, _, fs in os.walk(OUT) for f in fs)
print('%d entries, %.1f MB' % (len(copied), total / 1e6))
