"""POSIX job isolation: wall/CPU/address-space/file/output/process limits."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEFAULTS = dict(wall=60, cpu=45, memory_mb=1536, output_mb=16, files=128, processes=32)


def apply_limits(config=None):
    c = DEFAULTS | (config or {})
    for name, value in [('RLIMIT_CPU', c['cpu']),
                        ('RLIMIT_AS', c['memory_mb'] * 1024**2),
                        ('RLIMIT_FSIZE', c['output_mb'] * 1024**2),
                        ('RLIMIT_NOFILE', c['files']),
                        ('RLIMIT_NPROC', c['processes']), ('RLIMIT_CORE', 0)]:
        resource.setrlimit(getattr(resource, name), (value, value))


def run_process(argv, *, wall=60, memory_mb=1536, cwd=None):
    """No shell, bounded output on disk, kill the whole process group on timeout.

    This is resource containment, NOT a sandbox for executing untrusted code.
    """
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdout=out, stderr=err, cwd=cwd,
                                   start_new_session=True,
                                   preexec_fn=lambda: apply_limits(dict(memory_mb=memory_mb)))
        timed_out = False
        try:
            process.wait(timeout=wall)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        # Clean up any descendants left by a parent which exited early.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out.seek(0)
        err.seek(0)
        return dict(returncode=process.returncode, timed_out=timed_out,
                    stdout=out.read(16 * 1024**2).decode('utf-8', 'replace'),
                    stderr=err.read(16 * 1024**2).decode('utf-8', 'replace'))


def job(action, payload, *, wall=60):
    """Execute each analysis job in a fresh bounded Python worker."""
    with tempfile.TemporaryDirectory(prefix='darkforge-') as d:
        request = Path(d) / 'request.json'
        request.write_text(json.dumps(dict(action=action, payload=payload)))
        result = run_process([sys.executable, '-m', 'darkforge.worker', str(request)],
                             wall=wall, cwd=ROOT)
        if result['timed_out'] or result['returncode']:
            raise RuntimeError(f"Job failed ({result['returncode']}, timeout={result['timed_out']}): "
                               + result['stderr'][-2000:])
        return json.loads(result['stdout'])
