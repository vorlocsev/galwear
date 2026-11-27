"""Host-only regression tests for acceptance orchestration, not GNSS evidence."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'r800_gps_acceptance', ROOT / 'build/r800_gps_acceptance.py')
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class AcceptanceTests(unittest.TestCase):
    def run_case(self, mode, donor=True, qemu=False):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'report'
            candidate = out / 'gpsbridge'
            argv = ['acceptance', '--out', str(out)]
            if donor:
                argv += ['--ndk', str(Path(tmp) / 'ndk'),
                         '--donor', str(Path(tmp) / 'donor')]
            if qemu:
                argv += ['--qemu']
            snapshots = {'source': 'before'}
            calls = []

            class Process:
                def __init__(self, cmd, **kwargs):
                    self.cmd = cmd
                    calls.append(cmd)

                def wait(self, timeout=None):
                    cmd = self.cmd
                    if cmd[:2] == ['sh', 'src/tools/gps/build.sh']:
                        if mode != 'missing':
                            if mode == 'symlink':
                                target = Path(tmp) / 'target'
                                target.write_bytes(b'candidate')
                                candidate.symlink_to(target)
                            else:
                                candidate.write_bytes(b'candidate')
                        if mode == 'source-after-build':
                            snapshots['source'] = 'after'
                    elif len(cmd) > 1 and cmd[1] == 'build/r800_gps_link_gate.py':
                        if mode == 'replace':
                            candidate.write_bytes(b'replacement')
                        elif mode == 'remove':
                            candidate.unlink()
                        elif mode == 'audit-fails':
                            return 1
                    elif mode == 'source-before-build':
                        snapshots['source'] = 'after'
                    if mode == 'host-fails' and '-m' in cmd:
                        return 1
                    return 0

            def readelf(cmd, **kwargs):
                if cmd[1] == '-h':
                    return b'ELF32 little endian ARM Version5 EABI DYN REL soft-float ABI'
                if cmd[1] == '--dyn-syms':
                    return b'1: 00000000 4 FUNC GLOBAL DEFAULT 1 gps_get_hardware_interface'
                if cmd[1] == '-d':
                    return b''
                raise AssertionError(cmd)

            with patch.object(acceptance.sys, 'argv', argv), \
                 patch.object(acceptance, 'inputs', side_effect=lambda **kw: dict(snapshots)) as snapshot, \
                 patch.object(acceptance.subprocess, 'Popen', Process), \
                 patch.object(acceptance.subprocess, 'check_output', side_effect=readelf), \
                 patch.object(acceptance.os, 'getuid', return_value=1000), \
                 patch.object(acceptance.shutil, 'which', return_value='/mock/tool'), \
                 contextlib.redirect_stdout(io.StringIO()):
                rc = acceptance.main()
            self.assertTrue(all(call.kwargs == {'include_donor': donor, 'include_qemu': qemu}
                                for call in snapshot.call_args_list))
            report = json.loads((out / 'report.json').read_text())
            self.assertFalse(report['safe_to_flash'])
            self.assertFalse(report['vendor_abi_verified'])
            self.assertFalse(report['gnss_runtime_verified'])
            self.assertFalse(report['signed_attestation'])
            checks = {row['name']: row['status'] for row in report['checks']}
            for row in report['checks']:
                if 'log' in row:
                    self.assertEqual(row['log_sha256'],
                                     hashlib.sha256((out / row['log']).read_bytes()).hexdigest())
            return rc, report, checks, calls

    def test_host_only(self):
        rc, report, checks, _ = self.run_case('ok', donor=False)
        self.assertEqual(rc, 0)
        self.assertEqual(checks['experimental-build'], 'NOT_TESTED')
        self.assertIsNone(report['experimental_binary_sha256'])

    def test_candidate_unchanged(self):
        rc, report, checks, _ = self.run_case('ok', qemu=True)
        self.assertEqual(rc, 0)
        self.assertEqual(checks['experimental-candidate-integrity'], 'PASS')
        self.assertEqual(report['experimental_binary_sha256'],
                         hashlib.sha256(b'candidate').hexdigest())
        self.assertEqual(checks['glibc_qemu'], 'PASS')

    def test_candidate_replaced_or_removed(self):
        for mode in ('replace', 'remove'):
            with self.subTest(mode=mode):
                rc, report, checks, _ = self.run_case(mode)
                self.assertEqual(rc, 2)
                self.assertEqual(report['status'], 'REVIEW_REQUIRED')
                self.assertEqual(checks['experimental-candidate-integrity'], 'FAIL')
                self.assertIsNone(report['experimental_binary_sha256'])

    def test_missing_or_symlink_candidate(self):
        for mode in ('missing', 'symlink'):
            with self.subTest(mode=mode):
                rc, report, checks, calls = self.run_case(mode)
                self.assertEqual(rc, 2)
                self.assertEqual(checks['experimental-candidate'], 'FAIL')
                self.assertIsNone(report['experimental_binary_sha256'])
                self.assertFalse(any(len(c) > 1 and c[1] == 'build/r800_gps_link_gate.py'
                                     for c in calls))

    def test_source_change_before_build(self):
        rc, report, checks, _ = self.run_case('source-before-build')
        self.assertEqual(rc, 2)
        self.assertFalse(report['host_inputs_unchanged'])
        self.assertEqual(checks['experimental-build'], 'BLOCKED')

    def test_source_change_after_build(self):
        rc, report, _, _ = self.run_case('source-after-build')
        self.assertEqual(rc, 2)
        self.assertFalse(report['host_inputs_unchanged'])
        self.assertEqual(report['status'], 'REVIEW_REQUIRED')

    def test_failed_host_blocks_build(self):
        rc, _, checks, _ = self.run_case('host-fails')
        self.assertEqual(rc, 2)
        self.assertEqual(checks['experimental-build'], 'BLOCKED')

    def test_failed_audit_blocks_qemu(self):
        rc, report, checks, _ = self.run_case('audit-fails', qemu=True)
        self.assertEqual(rc, 2)
        self.assertEqual(checks['experimental-link-audit'], 'FAIL')
        self.assertEqual(checks['glibc_qemu'], 'BLOCKED')
        self.assertIsNone(report['experimental_binary_sha256'])


class EvidenceMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)
        self.expected = {'native-client-0': ('host', 'PASS'),
                         'experimental-build': ('donor_build', 'NOT_TESTED')}
        self.log = self.out / 'native-client-0.log'
        self.log.write_bytes(b'host result')
        self.rows = [
            dict(name='native-client-0', group='host', status='PASS',
                 exit_code=0, log=self.log.name,
                 log_sha256=hashlib.sha256(self.log.read_bytes()).hexdigest()),
            dict(name='experimental-build', group='donor_build', status='NOT_TESTED'),
        ]

    def errors(self):
        return acceptance.evidence_errors(self.rows, self.out, self.expected)

    def test_complete_matrix(self):
        self.assertEqual(self.errors(), [])

    def test_missing_result(self):
        self.rows.pop()
        self.assertTrue(any('missing result' in e for e in self.errors()))

    def test_duplicate_result(self):
        self.rows.append(dict(self.rows[0]))
        self.assertTrue(any('duplicate result' in e for e in self.errors()))

    def test_wrong_group_or_status(self):
        for key, value in [('group', 'qemu_synthetic'), ('status', 'NOT_TESTED')]:
            with self.subTest(key=key):
                original = self.rows[0][key]
                self.rows[0][key] = value
                self.assertTrue(self.errors())
                self.rows[0][key] = original

    def test_missing_or_changed_log(self):
        self.log.write_bytes(b'changed')
        self.assertTrue(any('log digest mismatch' in e for e in self.errors()))
        self.log.unlink()
        self.assertTrue(any('missing or invalid log' in e for e in self.errors()))

    def test_log_symlink_rejected(self):
        target = self.out / 'target'
        target.write_bytes(self.log.read_bytes())
        self.log.unlink()
        self.log.symlink_to(target)
        self.assertTrue(self.errors())

    def test_pass_requires_zero_exit_and_exact_log_name(self):
        for key, value in [('exit_code', 1), ('exit_code', False),
                           ('log', '../outside.log'), ('log_sha256', None)]:
            with self.subTest(key=key, value=value):
                original = self.rows[0][key]
                self.rows[0][key] = value
                self.assertTrue(self.errors())
                self.rows[0][key] = original

    def test_requested_matrix(self):
        host = acceptance.expected_checks()
        donor = acceptance.expected_checks(donor=True)
        qemu = acceptance.expected_checks(donor=True, qemu=True)
        self.assertEqual(len(host), 43)
        self.assertEqual(len(donor), 45)
        self.assertEqual(len(qemu), 45)
        self.assertEqual(host['glibc_qemu'][1], 'NOT_TESTED')
        self.assertEqual(qemu['glibc_qemu'][1], 'PASS')
        self.assertEqual(donor['experimental-candidate-integrity'][1], 'PASS')

    def test_candidate_digest_mismatch(self):
        name = 'experimental-candidate-integrity'
        rows = [dict(name=name, group='donor_build', status='PASS',
                     candidate_sha256='wrong')]
        self.assertTrue(acceptance.evidence_errors(
            rows, self.out, {name: ('donor_build', 'PASS')}, 'expected'))

class SavedReportTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            'r800_gps_verify_report', ROOT / 'build/r800_gps_verify_report.py')
        self.verifier = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'r800_gps_acceptance': acceptance}):
            spec.loader.exec_module(self.verifier)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)

    def fixture(self, mode):
        donor, qemu = mode != 'host', mode == 'qemu'
        candidate = None
        if donor:
            path = self.out / 'gpsbridge'
            path.write_bytes(b'mock candidate')
            candidate = acceptance.digest(path)
        rows = []
        for name, (group, status) in acceptance.expected_checks(donor, qemu).items():
            row = dict(name=name, group=group, status=status)
            if name == 'experimental-candidate-integrity':
                row['candidate_sha256'] = candidate
            elif status == 'PASS':
                log = self.out / (name + '.log')
                log.write_bytes(b'mock log')
                row.update(exit_code=0, log=log.name, log_sha256=acceptance.digest(log))
            rows.append(row)
        return dict(schema=self.verifier.SCHEMA, status='REQUESTED_CHECKS_PASS',
                    evidence_errors=[], host_inputs_unchanged=True,
                    input_sha256={'source': '0' * 64}, checks=rows,
                    experimental_binary_sha256=candidate,
                    **dict.fromkeys(self.verifier.FLAGS, False))

    def verify(self, report, mode='host', check_sources=False):
        (self.out / 'report.json').write_text(json.dumps(report))
        return self.verifier.verify(self.out, mode, check_sources)

    def test_all_modes(self):
        for mode in ('host', 'donor', 'qemu'):
            with self.subTest(mode=mode):
                self.assertEqual(self.verify(self.fixture(mode), mode), [])

    def test_mode_cannot_be_downgraded(self):
        self.assertTrue(self.verify(self.fixture('host'), 'qemu'))
        self.assertTrue(self.verify(self.fixture('donor'), 'qemu'))

    def test_candidate_changed(self):
        report = self.fixture('donor')
        (self.out / 'gpsbridge').write_bytes(b'changed')
        self.assertTrue(self.verify(report, 'donor'))

    def test_log_changed(self):
        report = self.fixture('host')
        (self.out / report['checks'][0]['log']).write_bytes(b'changed')
        self.assertTrue(self.verify(report))

    def test_invalid_claims(self):
        for key, value in [('safe_to_flash', True), ('signed_attestation', True),
                           ('host_inputs_unchanged', False), ('evidence_errors', ['bad']),
                           ('input_sha256', {'source': 'bad'}), ('checks', [None])]:
            with self.subTest(key=key):
                report = self.fixture('host')
                report[key] = value
                self.assertTrue(self.verify(report))

    def test_duplicate_json_key(self):
        (self.out / 'report.json').write_text('{"schema":"a","schema":"b"}')
        self.assertTrue(self.verifier.verify(self.out, 'host'))

    def test_source_manifest_comparison(self):
        report = self.fixture('host')
        with patch.object(self.verifier, 'inputs', return_value=report['input_sha256']):
            self.assertEqual(self.verify(report, check_sources=True), [])
        with patch.object(self.verifier, 'inputs', return_value={'source': '1' * 64}):
            self.assertTrue(self.verify(report, check_sources=True))

    def test_missing_report(self):
        self.assertTrue(self.verifier.verify(self.out, 'host'))

if __name__ == '__main__':
    unittest.main()
