"""Host-only regression tests for acceptance orchestration, not GNSS evidence."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
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


if __name__ == '__main__':
    unittest.main()
