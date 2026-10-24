import argparse
import json
from pathlib import Path
import platform
import shutil
import sys
from .db import Database
from .limits import job
from .source import PROJECT


def parser():
    p = argparse.ArgumentParser(description='DarkForge-X: bounded, source-only Android research')
    p.add_argument('--db', default='work/findings.sqlite', help='Local SQLite database')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('doctor', help='Inspect supported tools without network calls')
    a = sub.add_parser('acquire', help='Get the pinned AOSP PermissionEnforcer component')
    a.add_argument('--destination', default='work/aosp')
    a.add_argument('--online', action='store_true', help='Opt in to public AOSP source download')
    a.add_argument('--ref', default='1cdfff555f4a21f71ccc978290e2e212e2f8b168')
    a = sub.add_parser('scan')
    a.add_argument('root')
    a.add_argument('--engine', choices=['auto', 'builtin', 'semgrep'], default='auto')
    a.add_argument('--fixture', action='store_true', help='Synthetic/local source; never label it AOSP')
    a = sub.add_parser('search')
    a.add_argument('root')
    a.add_argument('query')
    a = sub.add_parser('logs')
    a.add_argument('path')
    sub.add_parser('validate', help='Run only bundled synthetic local validation models')
    a = sub.add_parser('review')
    a.add_argument('id', type=int)
    a.add_argument('status', choices=['unconfirmed', 'needs-review', 'rejected'])
    a.add_argument('--note', required=True)
    a = sub.add_parser('report')
    a.add_argument('--destination', default='work/reports')
    a = sub.add_parser('dashboard', help='Export an offline interactive dashboard')
    a.add_argument('--source', default='work/aosp')
    a.add_argument('--destination', default='work/reports/dashboard.html')
    a = sub.add_parser('callgraph', help='Analyze the pinned phase-two service slice')
    a.add_argument('--source', default=str(PROJECT / 'vendor/phase2'))
    a.add_argument('--destination', default='evidence/phase2')
    a = sub.add_parser('serve')
    a.add_argument('--source', default='work/aosp')
    a.add_argument('--port', type=int, default=8765)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    db_path = str(Path(args.db).resolve())
    try:
        if args.command == 'doctor':
            result = dict(python=sys.version.split()[0], platform=platform.platform(),
                          git=shutil.which('git'), semgrep=shutil.which('semgrep'),
                          pdf='builtin PDF writer available; no dependency needed',
                          limits='POSIX wall=60s CPU=45s memory=1536MiB output=16MiB files=128 processes=32',
                          network='No connectivity assumed; acquire --online explicitly opts into public source HTTPS',
                          root=str(PROJECT))
        elif args.command == 'acquire':
            result = job('acquire', dict(destination=str(Path(args.destination).resolve()),
                                         offline=not args.online, ref=args.ref), wall=40)
        elif args.command == 'scan':
            result = job('scan', dict(root=str(Path(args.root).resolve()), engine=args.engine, fixture=args.fixture))
            db = Database(db_path)
            try:
                result['run_id'] = db.record(result)
            finally:
                db.close()
        elif args.command == 'search':
            result = job('search', dict(root=str(Path(args.root).resolve()), query=args.query), wall=15)
        elif args.command in {'logs', 'validate'}:
            result = job(args.command, dict(path=str(Path(args.path).resolve())) if args.command == 'logs' else {})
            db = Database(db_path)
            try:
                db.add_evidence(args.command, result)
            finally:
                db.close()
            if args.command == 'validate' and not result['passed']:
                print(json.dumps(result, indent=2))
                return 1
        elif args.command == 'review':
            db = Database(db_path)
            try:
                db.review(args.id, args.status, args.note)
            finally:
                db.close()
            result = dict(id=args.id, status=args.status)
        elif args.command == 'report':
            result = job('report', dict(db_path=db_path, destination=str(Path(args.destination).resolve())))
        elif args.command == 'dashboard':
            result = job('dashboard', dict(db_path=db_path, source_root=str(Path(args.source).resolve()),
                                           destination=str(Path(args.destination).resolve())))
        elif args.command == 'callgraph':
            result = job('callgraph', dict(root=str(Path(args.source).resolve()), destination=str(Path(args.destination).resolve())))
        elif args.command == 'serve':
            from .web import serve
            serve(db_path, Path(args.source).resolve(), args.port)
            return 0
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print('DarkForge-X: ' + str(exc), file=sys.stderr)
        return 1
