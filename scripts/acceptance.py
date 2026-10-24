"""Regenerate reproducible example evidence without touching normal work databases."""
import json
from pathlib import Path
import shutil
import sys
import tempfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from darkforge.db import Database, now
from darkforge.limits import job, run_process
from darkforge.source import PROJECT


def main():
    out = PROJECT / 'evidence'
    out.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='darkforge-acceptance-') as temp:
        root = Path(temp)
        source = root / 'aosp'
        manifest = job('acquire', dict(destination=str(source), offline=True))
        scan = job('scan', dict(root=str(source), engine='builtin', fixture=False))
        validation = job('validate', {})
        logs = job('logs', dict(path=str(PROJECT / 'samples/sanitizer.log')))
        db = Database(root / 'findings.sqlite')
        db.record(scan)
        db.record(scan)  # Demonstrate duplicate handling with exact counts.
        db.add_evidence('synthetic-validation', validation)
        db.add_evidence('synthetic-logs', logs)
        findings = db.list_findings()
        db.close()
        reports = job('report', dict(db_path=str(root / 'findings.sqlite'), destination=str(out)))
        dashboard = job('dashboard', dict(db_path=str(root / 'findings.sqlite'), source_root=str(source), destination=str(out / 'dashboard.html')))
        pdf_check = None
        if shutil.which('pdftotext'):
            check = run_process(['pdftotext', str(out / 'report.pdf'), '-'], wall=10)
            pdf_check = dict(returncode=check['returncode'], contains_commit=manifest['commit'] in check['stdout'])
            assert check['returncode'] == 0 and pdf_check['contains_commit']
        assert validation['passed'] and len(findings) == len(scan['findings'])
        assert all(f['seen'] == 2 and f['status'] == 'unconfirmed' for f in findings)
        result = dict(generated_at=now(), python=sys.version.split()[0],
                      source_commit=manifest['commit'], source_git_blob=manifest['files'][0]['git_blob_sha'],
                      aosp_hint_count=len(findings), scan_count=2, duplicate_seen_counts=sorted(set(f['seen'] for f in findings)),
                      independently_validated_aosp_vulnerabilities=0,
                      synthetic_validation=validation, log_event_count=len(logs['events']),
                      reports=[Path(p).name for p in reports['files']],
                      pdf_check=pdf_check, offline_dashboard=dict(file='dashboard.html',indexed_lines=dashboard['indexed_lines']),
                      semgrep_actual_execution=False, live_socket_server_verified=False,
                      limitations=['Shell proxy unreachable for source/Git downloads; connected GitHub tool supplied immutable source.',
                                   'Semgrep install unavailable; builtin fallback used. Adapter mocks do not validate Semgrep runtime.',
                                   'Socket creation forbidden; in-memory HTTP handler and offline dashboard tested.',
                                   'No Android build, Android runtime test or independently validated AOSP vulnerability.'])
        (out / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
        (out / 'scan.json').write_text(json.dumps(scan, indent=2) + '\n')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
