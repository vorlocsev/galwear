"""Bounded host /proc measurements for a synthetic daemon under QEMU."""
import os
from pathlib import Path

PROC = Path('/proc')
MAX_PROCESSES = 128
WARMUP = 2
RSS_BUDGET_KIB = 8192


def identity(pid):
    fields = (PROC / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[19])  # Linux stat field 22, process start time.


def executable(pid):
    st = (PROC / str(pid) / 'exe').stat()
    return st.st_dev, st.st_ino


def locate(root, binary):
    """Find exactly one matching executable in the launcher descendant tree."""
    if type(root) is not int or root <= 1:
        raise ValueError('Invalid launcher PID')
    st = Path(binary).stat()
    wanted = st.st_dev, st.st_ino
    pending, seen, matches = [root], set(), []
    root_id = identity(root)
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if len(seen) > MAX_PROCESSES:
            raise ValueError('Process tree exceeds measurement budget')
        base = PROC / str(pid)
        try:
            start = identity(pid)
            if executable(pid) == wanted:
                matches.append((pid, start))
            children = (base / 'task' / str(pid) / 'children').read_text().split()
            if identity(pid) != start:
                raise ValueError('Process identity changed during discovery')
            pending.extend(map(int, children))
        except FileNotFoundError:
            continue
    if identity(root) != root_id or len(matches) != 1:
        raise ValueError('Expected exactly one matching daemon process')
    return matches[0]


def sample(target):
    pid, start = target
    base = PROC / str(pid)
    if identity(pid) != start:
        raise ValueError('Daemon process identity changed')
    fields = dict(line.split(':', 1) for line in (base / 'status').read_text().splitlines() if ':' in line)
    rss = fields['VmRSS'].split()
    if len(rss) != 2 or rss[1] != 'kB':
        raise ValueError('Unexpected VmRSS format')
    fds = sum(1 for _ in (base / 'fd').iterdir())
    threads = int(fields['Threads'])
    if identity(pid) != start or threads < 1 or fds < 0:
        raise ValueError('Invalid or changed daemon sample')
    return {'fds': fds, 'threads': threads, 'rss_kib': int(rss[0])}


def review(samples, cycles):
    if type(cycles) is not int or cycles <= WARMUP or len(samples) != cycles:
        raise ValueError('Incomplete resource samples')
    for item in samples:
        if set(item) != {'fds', 'threads', 'rss_kib'} or any(type(v) is not int or v < 0 for v in item.values()) or item['threads'] < 1:
            raise ValueError('Invalid resource sample')
    baseline = samples[WARMUP-1]
    measured = samples[WARMUP-1:]
    growth = max(s['rss_kib'] for s in measured) - baseline['rss_kib']
    problems = []
    for name in ('fds', 'threads'):
        if any(s[name] != baseline[name] for s in measured):
            problems.append(name + '_count_changed')
    if growth > RSS_BUDGET_KIB:
        problems.append('rss_budget_exceeded')
    return {'status': 'RESOURCE_COUNTS_STABLE' if not problems else 'REVIEW_REQUIRED',
            'samples': samples, 'warmup_cycles': WARMUP, 'rss_growth_kib': growth,
            'rss_budget_kib': RSS_BUDGET_KIB, 'problems': problems,
            'scope': 'host process including emulator; sampled idle boundaries only',
            'fd_leak_verified': False, 'memory_leak_verified': False,
            'hardware_verified': False, 'safe_to_flash': False}
