"""Bounded host /proc measurements for a synthetic daemon under QEMU."""
from pathlib import Path

PROC = Path('/proc')
MAX_PROCESSES = 128
MAX_VISIBLE = 32768
WARMUP = 2
RSS_BUDGET_KIB = 8192


def record(pid):
    fields = (PROC / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[1]), int(fields[19])  # PPID and start time.


def identity(pid):
    return record(pid)[1]


def executable(pid):
    st = (PROC / str(pid) / 'exe').stat()
    return st.st_dev, st.st_ino


def locate(root, binary):
    """Find exactly one matching executable in the launcher descendant tree."""
    if type(root) is not int or root <= 1:
        raise ValueError('Invalid launcher PID')
    st = Path(binary).stat()
    wanted = st.st_dev, st.st_ino
    root_id = identity(root)
    # /proc/PID/task/PID/children is optional in Linux configurations.
    children = {}
    for i, path in enumerate(PROC.iterdir()):
        if i >= MAX_VISIBLE:
            raise ValueError('Visible process scan exceeds measurement budget')
        if not path.name.isdecimal():
            continue
        pid = int(path.name)
        try:
            parent, start = record(pid)
        except FileNotFoundError:
            continue
        children.setdefault(parent, []).append((pid, start))
    pending, seen, matches = [(root, root_id)], set(), []
    while pending:
        pid, start = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if len(seen) > MAX_PROCESSES:
            raise ValueError('Process tree exceeds measurement budget')
        if identity(pid) != start:
            raise ValueError('Process identity changed during discovery')
        if executable(pid) == wanted:
            matches.append((pid, start))
        pending.extend(children.get(pid, ()))
    if identity(root) != root_id or len(matches) != 1 or identity(matches[0][0]) != matches[0][1]:
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
