#!/usr/bin/env python3
"""Synthetic daemon failure and repeated connection acceptance; no hardware."""
import argparse
import json
from pathlib import Path
import re

from r800_gps_mock_peer import Peer, START, LIMIT, wait_log
from r800_gps_mock_resources import locate, sample, review as review_resources

STAGES = (2, 3, 4, 5, 6)
CYCLES = 8


def expected(stage):
    prefix = ['CAPS 1234', 'init 0', 'client connected']
    retry = ['start failed, re-init', 'CAPS 4321']
    if stage == 4:
        return prefix + ['session start -> 0', 'session stop -> -14', 'CAPS 4321']
    if stage == 6:
        return prefix + retry + ['re-init -11']
    prefix += retry + ['CAPS 1234', 're-init 0']
    if stage in (2, 3):
        return prefix + ['session start -> ' + str(-12 if stage == 2 else -13), 'CAPS 4321']
    if stage != 5:
        raise ValueError('Unsupported recovery stage')
    cycle = ['session start -> 0', 'session stop -> 0', 'client gone']
    return prefix + cycle + (['client connected'] + cycle) * (CYCLES - 1)


def review(raw, stage, rc):
    if type(stage) is not int or stage not in STAGES or len(raw) > LIMIT:
        raise ValueError('Invalid recovery input')
    if type(rc) is not int or rc != (0 if stage == 5 else 1):
        raise ValueError('Unexpected recovery exit status')
    lines = raw.decode('ascii').splitlines()
    auxiliary = (r'GpsInterface 0x[0-9a-fA-F]+ size 40',
                 r'listening on /opt/usr/r800dev/gps\.sock',
                 r'inject_time [1-9][0-9]* ref [0-9]+ unc 500 -> 0',
                 r'inject_location \(last fix, [0-9]+ min old\) acc (2000|25000) -> 0')
    actual = [line for line in lines if not any(re.fullmatch(p, line) for p in auxiliary)]
    if actual != expected(stage):
        raise ValueError('Unexpected recovery lifecycle sequence: ' + repr(actual))
    return {'status': 'MOCK_DAEMON_RECOVERY_MATCH', 'stage': stage,
            'connections': CYCLES if stage == 5 else 1,
            'synthetic_only': True, 'fd_leak_verified': False,
            'vendor_abi_verified': False, 'safe_to_flash': False}


def drive(path, log, stage, *, launcher_pid=None, qemu=None):
    if stage not in STAGES:
        raise ValueError('Unsupported recovery stage')
    wait_log(log, rb'listening on /opt/usr/r800dev/gps\.sock')
    target = None
    samples = []
    if stage == 5:
        if launcher_pid is None or qemu is None:
            raise ValueError('Resource measurement requires launcher PID and QEMU executable')
        target = locate(launcher_pid, qemu)
    for i in range(CYCLES if stage == 5 else 1):
        with Peer(path) as peer:
            peer.send(b'START\n')
            if stage in (4, 5):
                peer.expect(*START)
                peer.send(b'STOP\n')
                if stage == 5:
                    peer.expect(b'STATUS 2')
                    peer.silent()
                else:
                    peer.eof()
            else:
                peer.eof()
        if stage == 5:
            wait_log(log, b'client gone', i + 1)
            if locate(launcher_pid, qemu) != target:
                raise ValueError('Daemon process replaced between cycles')
            samples.append(sample(target))
    return review_resources(samples, CYCLES) if stage == 5 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('drive', 'review'))
    parser.add_argument('--stage', type=int, choices=STAGES, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--socket', type=Path)
    parser.add_argument('--exit-code', type=int)
    parser.add_argument('--launcher-pid', type=int)
    parser.add_argument('--qemu', type=Path)
    args = parser.parse_args()
    try:
        if args.mode == 'drive':
            if args.socket is None:
                raise ValueError('Socket required')
            resources = drive(args.socket, args.log, args.stage, launcher_pid=args.launcher_pid, qemu=args.qemu)
            result = {'status': 'MOCK_DAEMON_RECOVERY_DRIVE_COMPLETE', 'safe_to_flash': False}
            if resources is not None:
                result['resources'] = resources
                if resources['problems']:
                    result['status'] = 'REVIEW_REQUIRED'
        else:
            with args.log.open('rb') as stream:
                result = review(stream.read(LIMIT+1), args.stage, args.exit_code)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({'status': 'REVIEW_REQUIRED', 'problems': [str(exc)], 'safe_to_flash': False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 2 if result['status'] == 'REVIEW_REQUIRED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
