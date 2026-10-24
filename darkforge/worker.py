"""Internal worker; all public CLI analysis passes through limits.job."""
import json
from pathlib import Path
import sys


def dispatch(action, p):
    if action == 'scan':
        from .scanner import scan
        return scan(**p)
    if action == 'search':
        from .source import search
        return search(**p)
    if action == 'acquire':
        from .source import acquire
        return acquire(**p)
    if action == 'logs':
        from .logs import parse_log
        path = Path(p['path'])
        if path.stat().st_size > 1024 * 1024:
            raise ValueError('Log exceeds 1 MiB')
        return parse_log(path.read_text(errors='replace'))
    if action == 'validate':
        from .validation import validate
        return validate()
    if action == 'dashboard':
        from .web import export_dashboard
        return export_dashboard(**p)
    if action == 'report':
        from .reports import generate
        return generate(**p)
    raise ValueError('Unknown worker action')


if __name__ == '__main__':
    request = json.loads(Path(sys.argv[1]).read_text())
    try:
        print(json.dumps(dispatch(request['action'], request['payload'])))
    except Exception as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(1)
