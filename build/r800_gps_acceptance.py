#!/usr/bin/env python3
"""Run GNSS synthetic acceptance; never flash, sign or publish a release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PY_SUITES = ('acceptance', 'mock_transcript', 'mock_peer', 'mock_recovery', 'mock_resources', 'mock_xtra_transcript')
C_SUITES = ('client', 'cache', 'cache_read', 'lto_file')
ARM = ['clang', '--target=armv7a-linux-gnueabi', '-marm', '-mfloat-abi=softfp', '-mfpu=vfpv3-d16',
       '-O2', '--no-default-config', '-nostdinc', '-ffreestanding', '-fno-builtin',
       '-fno-stack-protector', '-Wall', '-Wextra', '-Werror']
QEMU_SUITES = ('glibc_qemu', 'mock_qemu', 'mock_xtra_qemu')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inputs(include_donor=False, include_qemu=False):
    paths = [Path(__file__), ROOT / 'build/r800_gps_verify_report.py',
             *ROOT.glob('src/tools/gps/*.h'),
             *(ROOT / 'tests' / ('test_r800_gps_' + s + '.py') for s in PY_SUITES),
             *(ROOT / 'build' / ('r800_gps_' + s + '.py') for s in PY_SUITES),
             *(ROOT / 'tests' / ('test_r800_gps_' + s + '.c') for s in (*C_SUITES, 'xtra_submit')),
             ROOT / 'tests/r800_mock_gps_hal.c']
    if include_donor:
        # Conservative closure: include R800 build helpers, including transitive
        # imports, rather than claiming that only host inputs attest the build.
        paths.extend((ROOT / 'src/tools/gps').glob('*.c'))
        paths.extend((ROOT / 'build').glob('r800_*.py'))
        paths.extend((ROOT / 'build').glob('r800_*.sh'))
        paths.extend(ROOT / name for name in (
            'src/tools/gps/gpsbridge.c', 'src/tools/gps/build.sh',
            'build/r800_gps_donor_snapshot.py', 'build/r800_gps_provenance.py',
            'build/r800_gps_link_gate.py', 'build/r800_gps_publish.py'))
    if include_qemu:
        paths.extend(ROOT / 'tests' / name for name in
                     ('r800_glibc_probe.c', 'r800_glibc_probe_plugin.c'))
        paths.extend(ROOT / 'build' / ('r800_gps_' + s + '.sh') for s in QEMU_SUITES)
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(paths))}


def candidate_digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('candidate missing or not a regular file')
    return digest(path)


def expected_checks(donor=False, qemu=False):
    """Minimum successful evidence matrix for the requested invocation."""
    expected = {'python-' + suite: ('host', 'PASS') for suite in PY_SUITES}
    for suite, abi in [(s, 0) for s in C_SUITES] + [('xtra_submit', i) for i in range(3)]:
        name = 'native-' + suite + '-' + str(abi)
        expected[name + '-compile'] = expected[name] = ('host', 'PASS')
    for abi in range(3):
        expected['arm-xtra-%d' % abi] = ('arm32_compile_only', 'PASS')
    for abi, stage, case in [(0, i, 0) for i in range(8)] + [(a, 0, c) for a in (1, 2) for c in range(1, 5)]:
        expected['arm-hal-%d-%d-%d' % (abi, stage, case)] = ('arm32_compile_only', 'PASS')
    expected['experimental-build'] = ('donor_build', 'PASS' if donor else 'NOT_TESTED')
    if donor:
        expected['experimental-link-audit'] = ('donor_build', 'PASS')
        expected['experimental-candidate-integrity'] = ('donor_build', 'PASS')
    for suite in QEMU_SUITES:
        expected[suite] = ('qemu_synthetic', 'PASS' if qemu else 'NOT_TESTED')
    return expected


def evidence_errors(rows, out, expected, candidate_hash=None):
    """Reject incomplete matrices and missing, changed or mislabelled logs."""
    errors, seen = [], set()
    for row in rows:
        name = row['name']
        if name in seen:
            errors.append(name + ': duplicate result')
        seen.add(name)
        if name not in expected or (row['group'], row['status']) != expected[name]:
            errors.append(name + ': unexpected group or status')
        if row['status'] != 'PASS':
            continue
        if name == 'experimental-candidate-integrity':
            if not candidate_hash or row.get('candidate_sha256') != candidate_hash:
                errors.append(name + ': candidate digest mismatch')
            continue
        if (type(row.get('exit_code')) is not int or row['exit_code'] != 0
                or row.get('log') != name + '.log'):
            errors.append(name + ': invalid execution evidence')
            continue
        try:
            if candidate_digest(out / row['log']) != row.get('log_sha256'):
                errors.append(name + ': log digest mismatch')
        except (OSError, ValueError):
            errors.append(name + ': missing or invalid log')
    errors.extend(name + ': missing result' for name in sorted(set(expected) - seen))
    return errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True, help='new evidence directory outside checkout')
    p.add_argument('--ndk', type=Path)
    p.add_argument('--donor', type=Path)
    p.add_argument('--qemu', action='store_true', help='explicitly execute synthetic guests with trusted donor glibc')
    args = p.parse_args()
    if bool(args.ndk) != bool(args.donor) or (args.qemu and not args.ndk):
        p.error('--ndk and --donor must be paired; --qemu requires both')
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        p.error('--out must be outside the checkout')
    def snapshot():
        return inputs(include_donor=bool(args.ndk), include_qemu=args.qemu)

    before = snapshot()
    out.mkdir(mode=0o700, exist_ok=False)
    env = dict(os.environ, LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1',
               R800_XTRA_ABI='0', R800_TIZEN_ARCHIVE='', R800_HOST_SNAPSHOT='0')
    for key in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'OBJC_INCLUDE_PATH',
                'LIBRARY_PATH', 'COMPILER_PATH', 'GCC_EXEC_PREFIX', 'CCC_OVERRIDE_OPTIONS',
                'CLANG_CONFIG_FILE', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'PYTHONPATH'):
        env.pop(key, None)
    rows = []

    def run(name, group, cmd, timeout=30, verify=None):
        log = out / (name + '.log')
        status, rc = 'FAIL', None
        with log.open('wb') as stream:
            try:
                proc = subprocess.Popen(cmd, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                        start_new_session=True)
                try:
                    rc = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                    stream.write(b'ACCEPTANCE_TIMEOUT\n')
                if rc == 0:
                    if verify:
                        verify(stream)
                    status = 'PASS'
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                stream.write((str(exc) + '\n').encode())
        rows.append(dict(name=name, group=group, status=status, exit_code=rc,
                         log=log.name, log_sha256=digest(log)))
        print(name + '=' + status, flush=True)
        return status == 'PASS'

    def blocked(name, group, reason, status='BLOCKED'):
        rows.append(dict(name=name, group=group, status=status, reason=reason))
        print(name + '=' + status, flush=True)

    def arm_check(path, shared):
        def check(stream):
            header = subprocess.check_output(['readelf', '-h', str(path)], env=env, timeout=10)
            stream.write(header)
            required = [b'ELF32', b'little endian', b'ARM', b'Version5 EABI', b'DYN' if shared else b'REL']
            if any(x not in header for x in required) or b'hard-float ABI' in header or (shared and b'soft-float ABI' not in header):
                raise ValueError('Unexpected ARM ELF header')
            if shared:
                syms = subprocess.check_output(['readelf', '--dyn-syms', '-W', str(path)], env=env, timeout=10)
                stream.write(syms)
                entries = [l.split() for l in syms.splitlines() if len(l.split()) >= 8 and l.split()[0].endswith(b':')]
                exports = [l[7] for l in entries if l[4:6] == [b'GLOBAL', b'DEFAULT'] and l[6] != b'UND']
                if exports != [b'gps_get_hardware_interface'] or any(l[6] == b'UND' for l in entries):
                    raise ValueError('Unexpected HAL dynamic symbols')
                dynamic = subprocess.check_output(['readelf', '-d', str(path)], env=env, timeout=10)
                stream.write(dynamic)
                if any(x in dynamic for x in (b'(NEEDED)', b'(RPATH)', b'(RUNPATH)', b'(RELA)', b'(RELR)')):
                    raise ValueError('Unexpected HAL dynamic tags')
        return check

    with tempfile.TemporaryDirectory(prefix='r800-acceptance-') as tmp:
        work = Path(tmp)
        for suite in PY_SUITES:
            run('python-' + suite, 'host', [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p',
                                          'test_r800_gps_' + suite + '.py', '-v'])
        for suite, abi in [(s, 0) for s in C_SUITES] + [('xtra_submit', i) for i in range(3)]:
            name = 'native-' + suite + '-' + str(abi)
            binary = work / name
            if run(name + '-compile', 'host', ['cc', '-O2', '-Wall', '-Wextra', '-Werror',
                   *(['-Wno-unused-function'] if suite in ('cache_read', 'lto_file') else []), '-pthread', '-DR800_XTRA_ABI=' + str(abi), '-Isrc/tools/gps',
                   'tests/test_r800_gps_' + suite + '.c', '-o', str(binary)]):
                run(name, 'host', [str(binary)])
            else:
                blocked(name, 'host', 'native compile failed')
        for abi in range(3):
            target = work / ('xtra-%d.o' % abi)
            run('arm-xtra-%d' % abi, 'arm32_compile_only', ARM + ['-DR800_XTRA_ABI=' + str(abi), '-Isrc/tools/gps',
                '-c', 'tests/test_r800_gps_xtra_submit.c', '-o', str(target)], verify=arm_check(target, False))
        for abi, stage, case in [(0, i, 0) for i in range(8)] + [(a, 0, c) for a in (1, 2) for c in range(1, 5)]:
            name = 'arm-hal-%d-%d-%d' % (abi, stage, case)
            target = work / (name + '.so')
            run(name, 'arm32_compile_only', ARM + ['-fPIC', '-fvisibility=hidden', '-shared', '-nostdlib', '-fuse-ld=lld',
                '-Wl,--hash-style=sysv,-z,noexecstack,-z,now,--no-undefined', '-DR800_XTRA_ABI=' + str(abi),
                '-DMOCK_FAIL=' + str(stage), '-DMOCK_XTRA_CASE=' + str(case), '-o', str(target),
                'tests/r800_mock_gps_hal.c'], verify=arm_check(target, True))
    host_ok = all(r['status'] == 'PASS' for r in rows)
    unchanged = before == snapshot()
    candidate = out / 'gpsbridge'
    build_ok = False
    candidate_hash = None
    if not args.ndk:
        blocked('experimental-build', 'donor_build', 'NDK r27c and trusted Tizen glibc not supplied', 'NOT_TESTED')
    elif not host_ok or not unchanged:
        blocked('experimental-build', 'donor_build', 'host acceptance or source stability failed')
    else:
        build_ok = run('experimental-build', 'donor_build', ['sh', 'src/tools/gps/build.sh',
                       str(args.ndk.resolve()), str(args.donor.resolve()), str(candidate)], timeout=600)
        if build_ok:
            try:
                candidate_hash = candidate_digest(candidate)
            except (OSError, ValueError) as exc:
                blocked('experimental-candidate', 'donor_build', str(exc), 'FAIL')
                build_ok = False
        if build_ok:
            build_ok = run('experimental-link-audit', 'donor_build', [sys.executable, 'build/r800_gps_link_gate.py',
                           '--binary', str(candidate), '--libdir', str(args.donor.resolve())])
    for suite in QEMU_SUITES:
        if not args.qemu:
            blocked(suite, 'qemu_synthetic', 'explicit --qemu not requested', 'NOT_TESTED')
        elif not build_ok or os.getuid() == 0 or not all(shutil.which(x) for x in ('qemu-arm-static', 'bwrap')):
            blocked(suite, 'qemu_synthetic', 'requires audited build, unprivileged user, QEMU and bubblewrap')
        else:
            run(suite, 'qemu_synthetic', ['sh', 'build/r800_gps_' + suite + '.sh',
                str(args.ndk.resolve()), str(args.donor.resolve())], timeout=900)
    if build_ok:
        try:
            if candidate_digest(candidate) != candidate_hash:
                raise ValueError('candidate changed after build or during audit/QEMU')
        except (OSError, ValueError) as exc:
            blocked('experimental-candidate-integrity', 'donor_build', str(exc), 'FAIL')
            build_ok = False
        else:
            rows.append(dict(name='experimental-candidate-integrity', group='donor_build',
                             status='PASS', candidate_sha256=candidate_hash))
            print('experimental-candidate-integrity=PASS', flush=True)
    unchanged = unchanged and before == snapshot()
    errors = evidence_errors(rows, out, expected_checks(bool(args.ndk), args.qemu),
                             candidate_hash if build_ok else None)
    if not unchanged:
        errors.append('requested source inputs changed')
    ok = not errors
    report = dict(schema='galwear-r800-gps-acceptance-v1', status='REQUESTED_CHECKS_PASS' if ok else 'REVIEW_REQUIRED',
                  input_sha256=before, host_inputs_unchanged=unchanged, checks=rows,
                  evidence_errors=errors,
                  experimental_binary_sha256=candidate_hash if build_ok else None,
                  vendor_abi_verified=False, gnss_runtime_verified=False, safe_to_flash=False, signed_attestation=False)
    (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return 0 if ok else 2


if __name__ == '__main__':
    raise SystemExit(main())
