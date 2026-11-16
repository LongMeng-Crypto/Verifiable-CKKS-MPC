#!/usr/bin/env python3

import argparse
import fcntl
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

MIB = 1024 * 1024

# Returns total and available physical memory from the Linux kernel.
def available_memory():
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        if key in ('MemTotal', 'MemAvailable'):
            values[key] = int(value.split()[0]) * 1024
    return values['MemTotal'], values['MemAvailable']

# Returns the smallest exposed remaining cgroup memory allowance.
def cgroup_headroom():

    root = Path('/sys/fs/cgroup')
    paths = [root]
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        if line.startswith('0::'):
            current = root / line[3:].lstrip('/')
            if current.is_relative_to(root):
                paths.extend([current, *[p for p in current.parents if p.is_relative_to(root)]])
    remaining = []
    for path in paths:
        try:
            maximum = (path / 'memory.max').read_text().strip()
            if maximum != 'max':
                remaining.append(max(0, int(maximum) - int((path / 'memory.current').read_text())))
        except FileNotFoundError:
            pass
    return min(remaining) if remaining else None

# Estimates the resident memory of every process in the command group.
def group_rss(group):
    total = 0
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            stat = (item / 'stat').read_text()
            fields = stat[stat.rfind(')') + 2:].split()
            if int(fields[2]) == group:
                total += int((item / 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    return total

# Terminates the command process group and waits for its exit.
def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()

# Runs a development command within the configured memory budget.
def main():
    parser = argparse.ArgumentParser(description="Run a development command within the memory budget.")
    parser.add_argument('--limit-mib', type=int, default=8192)
    parser.add_argument('--reserve-mib', type=int, default=8192)
    parser.add_argument('--expected-mib', type=int, default=0)
    parser.add_argument('--timeout-seconds', type=int, default=1800)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or min(args.limit_mib, args.reserve_mib, args.timeout_seconds) <= 0 or args.expected_mib < 0:
        parser.error('a command and positive limits are required')
    if args.reserve_mib < 8192:
        parser.error('at least 8192 MiB of available RAM must remain reserved')
    if args.limit_mib > 8192:
        parser.error('development budget exceeds 8192 MiB; stop and obtain an explicit new budget')
    if args.expected_mib > args.limit_mib:
        parser.error(f'expected {args.expected_mib} MiB exceeds the development budget; job not started')
    total, available = available_memory()
    limit, reserve = args.limit_mib * MIB, args.reserve_mib * MIB
    headroom = cgroup_headroom()
    if available < limit + reserve or (headroom is not None and headroom < limit + reserve):
        parser.error('insufficient RAM/cgroup headroom for job plus reserve; job not started')
    lock_path = Path(__file__).resolve().parents[1] / 'target' / 'memory-guard.lock'
    lock_path.parent.mkdir(exist_ok=True)
    with lock_path.open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('another guarded development job is running; job not started')
        env = os.environ.copy()
        env.setdefault('RAYON_NUM_THREADS', '4')
        env.setdefault('RUST_TEST_THREADS', '1')
        env.setdefault('CARGO_BUILD_JOBS', '1')
        # Applies inherited per-process address-space and core-dump limits.
        def child_limit():
            _, hard = resource.getrlimit(resource.RLIMIT_AS)
            cap = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        print(f'memory guard: RAM={total/MIB:.0f} MiB available={available/MIB:.0f} MiB; '
              f'group RSS budget={args.limit_mib} MiB; per-process AS cap={args.limit_mib} MiB; '
              f'available reserve={args.reserve_mib} MiB', file=sys.stderr, flush=True)
        process = subprocess.Popen(command, env=env, start_new_session=True, preexec_fn=child_limit)
        # Terminates the guarded process group when a signal arrives.
        def interrupted(signum, _frame):
            stop_group(process)
            raise SystemExit(128 + signum)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        start, peak, reason = time.monotonic(), 0, None
        try:
            while process.poll() is None:
                rss = group_rss(process.pid)
                peak = max(peak, rss)
                _, free = available_memory()
                headroom = cgroup_headroom()
                if rss >= limit:
                    reason = 'process-group RSS reached budget'
                elif free < reserve or (headroom is not None and headroom < reserve):
                    reason = 'available memory dropped below reserve'
                elif time.monotonic() - start > args.timeout_seconds:
                    reason = 'job timeout'
                if reason:
                    stop_group(process)
                    break
                time.sleep(0.1)
        finally:
            stop_group(process)
        print(f'memory guard: observed group peak RSS={peak/MIB:.1f} MiB'
              + (f'; stopped: {reason}' if reason else f'; exit={process.returncode}'),
              file=sys.stderr, flush=True)
        return 125 if reason else (process.returncode if process.returncode >= 0 else 128-process.returncode)

if __name__ == '__main__':
    raise SystemExit(main())
