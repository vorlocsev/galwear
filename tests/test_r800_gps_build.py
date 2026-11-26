"""Host-only shell contract tests: fake NDK and gate, no ARM execution."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from r800_gps_repeatability import compare
from r800_gps_provenance import HEADERS

SCRIPT = Path(__file__).resolve().parents[1] / 'src/tools/gps/build.sh'
LIBS = ('libc.so.6', 'libdl.so.2', 'libpthread.so.0', 'ld-linux.so.3')

READ_ELF = '''#!/usr/bin/env python3
import sys
from pathlib import Path
p = Path(sys.argv[-1])
assert Path(sys.argv[0]).parent.name == 'tools'
kind = p.read_text()
if p.name != 'gpsbridge':
    assert p.parent.name == 'libs', 'readelf must inspect the snapshot'
print('Class: ' + ('ELF64' if kind == 'wide' else 'ELF32'))
print('Data: ' + ('big endian' if kind == 'big' else 'little endian'))
print('Machine: ' + ('AArch64' if kind == 'foreign' else 'ARM'))
print('Type: ' + ('EXEC' if kind == 'exec' else 'DYN (Shared object file)'))
print('/lib/ld-linux.so.3')
if kind == 'broken':
    sys.exit(1)
'''
CLANG = '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
assert not any(k in os.environ for k in ('CPATH', 'LIBRARY_PATH', 'CCC_OVERRIDE_OPTIONS'))
Path(os.environ['TEST_MARKER']).touch()
output = Path(sys.argv[sys.argv.index('-o') + 1])
source = output.parent / 'sources/gpsbridge.c'
assert Path(sys.argv[0]) == output.parent / 'tools/clang'
assert '--ld-path=' + str(output.parent / 'tools/ld.lld') in sys.argv
assert (output.parent / 'tools/ld.lld').stat().st_mode & 0o777 == 0o500
assert str(source) in sys.argv
assert source.read_text() == '/* synthetic fixture */'
assert source.stat().st_mode & 0o777 == 0o400
if os.environ.get('TEST_MODE') == 'tool-snapshot-mutate':
    p = output.parent / 'tools/ld.lld'
    p.chmod(0o600)
    p.write_text('mutated linker')
    p.chmod(0o500)
if os.environ.get('TEST_MODE') == 'snapshot-compiler-mutate':
    p = source.parent / 'gps_abi.h'
    p.chmod(0o600)
    p.write_text('mutated')
    p.chmod(0o400)
value = 'bridge'
if os.environ.get('TEST_MODE') == 'nonrepeatable' and Path.cwd().name == 'second':
    value = 'different'
output.write_text(value)
'''
GATE = '''import hashlib, json, os, sys
from pathlib import Path
mode = os.environ['TEST_MODE']
out = Path(os.environ['TEST_OUT'])
if mode == 'reject':
    sys.exit(2)
binary = Path(sys.argv[sys.argv.index('--binary') + 1])
libs = Path(sys.argv[sys.argv.index('--libdir') + 1])
report = {'status': 'STATIC_GLIBC_CLOSURE_ONLY', 'static_closure_pass': True,
          'safe_to_flash': False, 'runtime_verified': False, 'problems': [],
          'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'donor_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in libs.iterdir()}}
if mode == 'wrong-digest':
    report['sha256'] = '0' * 64
if mode == 'wrong-donor-digest':
    report['donor_sha256']['libc.so.6'] = '0' * 64
if mode == 'bad-scope':
    report['safe_to_flash'] = True
if mode == 'binary-mutate':
    binary.write_bytes(b'changed')
if mode == 'binary-symlink':
    binary.unlink()
    binary.symlink_to(libs / 'libc.so.6')
print(json.dumps(report))
if mode == 'source-code-mutate':
    (out.parent / 'src/tools/gps/gpsbridge.c').write_text('changed source')
if mode == 'snapshot-extra':
    (binary.parent / 'sources/extra.h').write_text('unexpected')
if mode == 'header-mutate':
    (out.parent / 'src/tools/gps/gps_abi.h').write_text('changed header')
if mode == 'tool-snapshot-extra':
    (binary.parent / 'tools/extra').write_text('unexpected')
if mode == 'tool-mutate':
    (out.parent / 'ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld').write_text('changed linker')
if mode == 'mutate':
    (Path(sys.argv[sys.argv.index('--libdir') + 1]) / 'libc.so.6').write_text('changed')
if mode == 'source-mutate':
    (out.parent / 'donor/libc.so.6').write_text('changed')
if mode == 'source-replace':
    source = out.parent / 'donor'
    source.rename(out.parent / 'old-donor')
    source.mkdir()
    for item in (out.parent / 'old-donor').iterdir():
        (source / item.name).write_bytes(item.read_bytes())
if mode == 'directory':
    out.mkdir()
if mode == 'symlink':
    out.symlink_to(out.parent, target_is_directory=True)
if mode == 'file':
    out.write_text('competitor')
'''


class BuildContract(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.script = self.root / 'src/tools/gps/build.sh'
        self.script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, self.script)
        (self.script.parent / 'gpsbridge.c').write_text('/* synthetic fixture */')
        # Use the production snapshot inventory so adding a required header
        # cannot silently leave the synthetic fixture behind.
        for name in HEADERS:
            self.assertTrue((SCRIPT.parent / name).is_file(), name)
            (self.script.parent / name).write_text('/* synthetic header */')
        self.ndk = self.root / 'ndk'
        tc = self.ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin'
        tc.mkdir(parents=True)
        (self.ndk / 'source.properties').write_text('Pkg.Revision = 27.2.12479018\n')
        for name, body in [('llvm-readelf', READ_ELF), ('clang', CLANG)]:
            path = tc / name
            path.write_text(body)
            path.chmod(0o755)
        (tc / 'ld.lld').write_text('synthetic linker')
        (self.root / 'build').mkdir()
        for name in ('r800_gps_donor_snapshot.py', 'r800_android_userspace_preflight.py',
                     'r800_gps_publish.py', 'r800_gps_provenance.py',
                     'r800_android_linker_audit.py', 'r800_tizen_dependencies.py',
                     'r800_pack_tizen_stage.py', 'r800_verify_tizen_stage.py',
                     'r800_gps_host_elf.py', 'r800_gps_host_snapshot.py', 'r800_gps_host_trace.py'):
            shutil.copyfile(SCRIPT.parents[3] / 'build' / name,
                            self.root / 'build' / name)
        (self.root / 'build/r800_gps_link_gate.py').write_text(GATE)
        self.libs = self.root / 'donor'
        self.libs.mkdir()
        for name in LIBS:
            (self.libs / name).write_text('valid')
        self.out = self.root / 'output'
        self.marker = self.root / 'clang-called'

    def run_build(self, mode='ok'):
        env = dict(os.environ, TEST_MODE=mode, TEST_OUT=str(self.out),
                   TEST_MARKER=str(self.marker), R800_XTRA_ABI='0')
        result = subprocess.run(['sh', str(self.script), str(self.ndk),
                                 str(self.libs), str(self.out)], env=env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(list(self.root.glob('.gpsbridge.*')), [])
        return result

    def reject_donor(self, value):
        (self.libs / LIBS[0]).write_text(value)
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_success(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.out.read_text(), 'bridge')
        self.assertIn('NON-RELEASE', result.stdout)
        evidence = [json.loads(line) for line in result.stdout.splitlines()
                    if line.startswith('{"audit_sha256":')]
        self.assertEqual(len(evidence), 1)
        self.assertFalse(evidence[0]['signed_attestation'])
        self.assertFalse(evidence[0]['safe_to_flash'])
        self.assertIsNone(evidence[0]['tizen_archive'])
        self.assertIn('--target=armv7a-linux-gnueabi', evidence[0]['inputs']['argv'])
        self.assertEqual(evidence[0]['inputs']['compiler_contract'], 'freestanding-snapshot-v5')
        self.assertEqual(evidence[0]['inputs']['xtra_abi'], 0)
        host = evidence[0]['inputs']['inputs']['host_elf']
        self.assertEqual(host['status'], 'HOST_REVIEW_REQUIRED')
        self.assertFalse(host['host_isolated'])
        self.assertIsNone(evidence[0]['inputs']['inputs']['host_snapshot'])
        self.assertEqual(evidence[0]['inputs']['tool_snapshot'],
                         {'clang': 'clang', 'ld.lld': 'lld', 'llvm-readelf': 'readelf'})
        for name in HEADERS:
            self.assertIn(name, evidence[0]['inputs']['inputs'])

    def test_compiler_environment_is_filtered(self):
        with mock.patch.dict(os.environ, {"CPATH": "/foreign", "LIBRARY_PATH": "/foreign",
                                          "CCC_OVERRIDE_OPTIONS": "+-O0"}):
            result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_compiler_argument_contract(self):
        from r800_gps_provenance import validate_command
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = next(json.loads(line) for line in result.stdout.splitlines()
                        if line.startswith('{"audit_sha256":'))
        argv = evidence["inputs"]["argv"]
        self.assertEqual(validate_command(self.root, self.ndk, argv), 0)
        for args in (argv + ["-I/tmp/foreign"],
                     argv + ["@/tmp/response"],
                     [x for x in argv if x != "-nostdinc"],
                     ["-DR800_XTRA_ABI=3" if x == "-DR800_XTRA_ABI=0" else x for x in argv],
                     ["-O3" if x == "-O2" else x for x in argv],
                     ["/tmp/libc.so.6" if x.endswith("/libs/libc.so.6") else x for x in argv],
                     [str(self.script.parent / "gpsbridge.c") if x.endswith("/sources/gpsbridge.c") else x for x in argv]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                validate_command(self.root, self.ndk, args)

    def test_source_snapshot_mutations(self):
        for mode in ('snapshot-compiler-mutate', 'snapshot-extra'):
            with self.subTest(mode=mode):
                result = self.run_build(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.out.exists())

    def test_tool_snapshot_mutations(self):
        for mode in ('tool-snapshot-mutate', 'tool-snapshot-extra'):
            with self.subTest(mode=mode):
                self.marker.unlink(missing_ok=True)
                result = self.run_build(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.out.exists())

    def test_captured_host_mode_rejects_non_elf_tools(self):
        with mock.patch.dict(os.environ, {'R800_HOST_SNAPSHOT': '1'}):
            result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Host closure requires review', result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_strict_host_audit_rejects_non_elf_tools(self):
        with mock.patch.dict(os.environ, {"R800_REQUIRE_HOST_ELF": "1"}):
            result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Host tool dependencies require review", result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_missing_tool_blocks_compiler(self):
        (self.ndk / 'toolchains/llvm/prebuilt/linux-x86_64/bin/ld.lld').unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_missing_header_blocks_compiler(self):
        (self.script.parent / 'gps_frame.h').unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_invalid_archive_blocks_compiler(self):
        archive = self.root / "invalid.tar"
        archive.write_bytes(b"invalid archive")
        with mock.patch.dict(os.environ, {"R800_TIZEN_ARCHIVE": str(archive)}):
            result = self.run_build()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_repeatability(self):
        env = dict(TEST_MODE='ok', TEST_OUT=str(self.out), TEST_MARKER=str(self.marker))
        with mock.patch.dict(os.environ, env):
            result = compare(self.script, self.ndk, self.libs, 0, timeout=30)
        self.assertEqual(result['status'], 'LOCAL_REPEATABILITY_PASS')
        self.assertFalse(result['safe_to_flash'])
        self.assertEqual(result['runs'][0], result['runs'][1])

    def test_repeatability_different_binary(self):
        env = dict(TEST_MODE='nonrepeatable', TEST_OUT=str(self.out), TEST_MARKER=str(self.marker))
        with mock.patch.dict(os.environ, env):
            result = compare(self.script, self.ndk, self.libs, 0, timeout=30)
        self.assertEqual(result['status'], 'LOCAL_REPEATABILITY_FAIL')
        self.assertEqual(result['differences'], ['binary_sha256'])
        self.assertFalse(result['safe_to_flash'])

    def test_wrong_class(self):
        self.reject_donor('wide')

    def test_wrong_machine(self):
        self.reject_donor('foreign')

    def test_wrong_endianness(self):
        self.reject_donor('big')

    def test_wrong_type(self):
        self.reject_donor('exec')

    def test_readelf_failure_even_with_valid_output(self):
        self.reject_donor('broken')

    def test_donor_symlink(self):
        p = self.libs / LIBS[0]
        p.unlink()
        p.symlink_to(self.libs / LIBS[1])
        self.assertNotEqual(self.run_build().returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_empty_donor(self):
        self.reject_donor('')

    def test_oversized_donor(self):
        with (self.libs / LIBS[0]).open('wb') as stream:
            stream.truncate(64 * 1024**2 + 1)
        self.assertNotEqual(self.run_build().returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_fifo_donor(self):
        p = self.libs / LIBS[0]
        p.unlink()
        os.mkfifo(p)
        self.assertNotEqual(self.run_build().returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_source_mutation_after_link(self):
        self.assertNotEqual(self.run_build('source-mutate').returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_source_directory_replaced_after_link(self):
        self.assertNotEqual(self.run_build('source-replace').returncode, 0)
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.out.exists())

    def test_audit_digest_or_scope_mismatch(self):
        for mode in ('wrong-digest', 'wrong-donor-digest', 'bad-scope',
                     'binary-mutate', 'binary-symlink'):
            with self.subTest(mode=mode):
                self.assertNotEqual(self.run_build(mode).returncode, 0)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.out.exists())

    def test_provenance_changes(self):
        for mode in ('source-code-mutate', 'header-mutate', 'tool-mutate'):
            with self.subTest(mode=mode):
                self.marker.unlink(missing_ok=True)
                (self.script.parent / 'gpsbridge.c').write_text('/* synthetic fixture */')
                (self.script.parent / 'gps_abi.h').write_text('/* synthetic header */')
                self.assertNotEqual(self.run_build(mode).returncode, 0)
                self.assertTrue(self.marker.exists())
                self.assertFalse(self.out.exists())

    def test_gate_failure(self):
        self.assertNotEqual(self.run_build('reject').returncode, 0)
        self.assertFalse(self.out.exists())

    def test_snapshot_mutation(self):
        self.assertNotEqual(self.run_build('mutate').returncode, 0)
        self.assertFalse(self.out.exists())

    def test_late_directory(self):
        self.assertNotEqual(self.run_build('directory').returncode, 0)
        self.assertTrue(self.out.is_dir())
        self.assertEqual(list(self.out.iterdir()), [])

    def test_late_symlink(self):
        self.assertNotEqual(self.run_build('symlink').returncode, 0)
        self.assertTrue(self.out.is_symlink())
        self.assertFalse((self.root / 'gpsbridge').exists())

    def test_late_file(self):
        self.assertNotEqual(self.run_build('file').returncode, 0)
        self.assertEqual(self.out.read_text(), 'competitor')


if __name__ == '__main__':
    unittest.main()
