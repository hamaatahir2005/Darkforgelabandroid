"""Bound the whole test suite, including nested workers and server smoke tests."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from darkforge.limits import run_process
result = run_process([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-v'], wall=90)
print(result['stdout'], end='')
print(result['stderr'], end='', file=sys.stderr)
if result['timed_out']:
    print('Test suite timed out', file=sys.stderr)
raise SystemExit(result['returncode'] or int(result['timed_out']))
