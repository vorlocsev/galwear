#!/usr/bin/env python3
"""Exact synthetic XTRA standalone transcript; no vendor ABI assertion."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_gps_mock_transcript import expected as gps_expected, MAX_LOG

MATRIX = ((0, 0),) + tuple((abi, case) for abi in (1, 2) for case in range(1, 6))


def expected(abi, case):
    if type(abi) is not int or type(case) is not int or (abi, case) not in MATRIX:
        raise ValueError('Unsupported XTRA scenario')
    base = gps_expected(0)
    prefix = ['CAPS a101', 'CAPS a102']
    extra = {
        0: [],
        1: prefix + ['CAPS a103', 'lto: injected 4 bytes -> 0'],
        2: prefix + [re.escape('lto: XTRA unavailable or init failed (3, -12)')],
        3: prefix + ['CAPS a103', 'lto: injected 4 bytes -> -13'],
        4: ['CAPS a101', re.escape('lto: XTRA unavailable or init failed (2, 0)')],
        5: ['lto: missing, unsafe, oversized or changed file'],
    }[case]
    return base[:4] + extra + base[4:]


def review(raw, abi, case, rc):
    patterns = expected(abi, case)
    if type(rc) is not int or not 0 <= rc <= 255 or len(raw) > MAX_LOG:
        raise ValueError('Invalid XTRA transcript or exit status')
    lines = raw.decode('ascii').splitlines()
    problems = []
    if len(lines) != len(patterns) or not all(re.fullmatch(p, s) for p, s in zip(patterns, lines)):
        problems.append('TRANSCRIPT_MISMATCH')
    if rc != 0:
        problems.append('GPS_LIFECYCLE_FAILED')
    return {'status': 'MOCK_XTRA_TRANSCRIPT_MATCH' if not problems else 'REVIEW_REQUIRED',
            'abi': abi, 'case': case, 'exit_code': rc, 'problems': problems,
            'log_sha256': hashlib.sha256(raw).hexdigest(),
            'synthetic_only': True, 'vendor_abi_verified': False,
            'lto_authenticity_verified': False, 'gnss_runtime_verified': False,
            'safe_to_flash': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--abi', type=int, required=True)
    p.add_argument('--case', type=int, required=True)
    p.add_argument('--exit-code', type=int, required=True)
    p.add_argument('--log', type=Path, required=True)
    args = p.parse_args()
    try:
        with args.log.open('rb') as stream:
            report = review(stream.read(MAX_LOG+1), args.abi, args.case, args.exit_code)
    except (OSError, ValueError) as exc:
        report = {'status': 'REVIEW_REQUIRED', 'problems': [str(exc)], 'safe_to_flash': False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report['status'] == 'MOCK_XTRA_TRANSCRIPT_MATCH' else 2


if __name__ == '__main__':
    raise SystemExit(main())
