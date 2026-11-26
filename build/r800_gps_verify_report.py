#!/usr/bin/env python3
"""Read-only validation of a saved GNSS acceptance evidence bundle."""
import argparse
import json
from pathlib import Path
import re
import sys

from r800_gps_acceptance import candidate_digest, evidence_errors, expected_checks, inputs

SCHEMA = 'galwear-r800-gps-acceptance-v1'
FLAGS = ('vendor_abi_verified', 'gnss_runtime_verified', 'safe_to_flash',
         'signed_attestation')
MAX_REPORT = 4 * 1024 * 1024


def sha256(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def verify(directory, mode, check_sources=False):
    """Return consistency errors; no commands or paths from JSON are executed."""
    if mode not in ('host', 'donor', 'qemu'):
        return ['invalid requested mode']
    out = Path(directory)
    donor, qemu = mode != 'host', mode == 'qemu'
    try:
        path = out / 'report.json'
        if out.is_symlink() or path.is_symlink() or not path.is_file():
            raise ValueError('report must be a regular file in a non-symlink directory')
        with path.open('rb') as stream:
            raw = stream.read(MAX_REPORT + 1)
        if len(raw) > MAX_REPORT:
            raise ValueError('report exceeds size limit')
        report = json.loads(raw, object_pairs_hook=unique_object)
    except (OSError, ValueError, RecursionError) as exc:
        return ['cannot read report: ' + str(exc)]
    if not isinstance(report, dict):
        return ['report must be an object']
    errors = []
    if report.get('schema') != SCHEMA:
        errors.append('unsupported schema')
    if report.get('status') != 'REQUESTED_CHECKS_PASS':
        errors.append('report does not claim requested checks passed')
    if report.get('evidence_errors') != []:
        errors.append('report contains evidence errors or lacks error list')
    if report.get('host_inputs_unchanged') is not True:
        errors.append('source stability not established')
    for flag in FLAGS:
        if report.get(flag) is not False:
            errors.append('invalid non-release flag: ' + flag)

    manifest = report.get('input_sha256')
    if not isinstance(manifest, dict) or not manifest or not all(
            isinstance(k, str) and k and sha256(v) for k, v in manifest.items()):
        errors.append('invalid source digest manifest')
    elif check_sources:
        try:
            if manifest != inputs(include_donor=donor, include_qemu=qemu):
                errors.append('source digest manifest differs from current checkout')
        except (OSError, ValueError) as exc:
            errors.append('cannot verify checkout sources: ' + str(exc))

    rows = report.get('checks')
    expected = expected_checks(donor, qemu)
    candidate_hash = report.get('experimental_binary_sha256')
    if donor:
        if not sha256(candidate_hash):
            errors.append('invalid candidate digest')
        else:
            try:
                if candidate_digest(out / 'gpsbridge') != candidate_hash:
                    errors.append('saved candidate digest mismatch')
            except (OSError, ValueError):
                errors.append('saved candidate missing or invalid')
    elif 'experimental_binary_sha256' not in report or candidate_hash is not None:
        errors.append('unexpected candidate digest in host mode')
    if not isinstance(rows, list) or not all(
            isinstance(row, dict) and all(isinstance(row.get(k), str)
                                           for k in ('name', 'group', 'status'))
            for row in rows):
        errors.append('invalid check row structure')
    else:
        errors.extend(evidence_errors(rows, out, expected, candidate_hash))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--mode', required=True, choices=('host', 'donor', 'qemu'),
                        help='expected invocation mode; never infer from report')
    parser.add_argument('--check-sources', action='store_true',
                        help='compare manifest against this trusted checkout')
    args = parser.parse_args()
    errors = verify(args.directory, args.mode, args.check_sources)
    print(json.dumps(dict(status='REVIEW_REQUIRED' if errors else 'CONSISTENCY_PASS',
                          mode=args.mode, checked_sources=args.check_sources,
                          errors=errors, signed_attestation=False,
                          safe_to_flash=False), indent=2))
    return 2 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
