"""Conservative review hints; absence of a hint never establishes security."""
import json
from pathlib import Path
import re
import shutil
from .source import files, verify_snapshot, digest, PROJECT
from .limits import run_process

ROOT = PROJECT


def load_rules():
    # JSON is valid YAML; one rule source feeds both engines.
    return json.loads((ROOT / 'rules/android.json').read_text())['rules']


def hint(rule, path, line, snippet, engine):
    meta = rule['metadata']
    return dict(rule=rule['id'], path=path, line=line, snippet=snippet[:1000],
                cwe=meta['cwe'], confidence=meta['confidence'],
                confidence_meaning='Pattern relevance only; not exploitability probability',
                title=rule['message'], recommendation=meta['recommendation'],
                hypothesis=meta['hypothesis'], status='unconfirmed', engine=engine)


def scan(root, engine='auto', fixture=False):
    root = Path(root).resolve()
    manifest = None if fixture else verify_snapshot(root)
    corpus = list(files(root))  # enforce source/file budgets before either engine
    version = digest(''.join(str(p.relative_to(root)) + ':' + digest(p.read_bytes())
                             for p in corpus).encode())
    binary = shutil.which('semgrep')
    if engine == 'semgrep' and not binary:
        raise RuntimeError('Semgrep is unavailable; use --engine builtin. It is not equivalent.')
    selected = 'semgrep' if binary and engine in {'semgrep', 'auto'} else 'builtin'
    rules = load_rules()
    findings = []
    diagnostic = 'Semgrep not installed; builtin lexical review only' if engine == 'auto' and not binary else ''
    if selected == 'semgrep':
        # Config is local, telemetry/version/network registry calls disabled.
        import os
        previous = {k: os.environ.get(k) for k in ['SEMGREP_SEND_METRICS', 'SEMGREP_ENABLE_VERSION_CHECK']}
        os.environ['SEMGREP_SEND_METRICS'] = 'off'
        os.environ['SEMGREP_ENABLE_VERSION_CHECK'] = '0'
        try:
            result = run_process([binary, 'scan', '--config', str(ROOT / 'rules/android.json'),
                                  '--json', '--metrics=off', '--disable-version-check',
                                  '--timeout', '5', '--max-memory', '512', '--jobs', '1',
                                  '--max-target-bytes', '1048576', str(root)], wall=40)
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        if result['returncode'] or result['timed_out']:
            raise RuntimeError('Semgrep failed: ' + result['stderr'][-1000:])
        output = json.loads(result['stdout'])
        if output.get('errors'):
            raise RuntimeError('Semgrep returned errors; analysis incomplete: ' + str(output['errors'])[:1000])
        for match in output.get('results', []):
            rule = next((r for r in rules if match['check_id'].endswith(r['id'])), None)
            if not rule:
                raise ValueError('Unknown Semgrep rule')
            path = Path(match['path'])
            if not path.is_absolute():
                path = Path.cwd() / path
            path = path.resolve()
            if not path.is_relative_to(root):
                raise ValueError('Semgrep result outside corpus')
            number = match['start']['line']
            line = path.read_text(errors='replace').splitlines()[number - 1]
            findings.append(hint(rule, str(path.relative_to(root)), number, line, selected))
    else:
        for path in corpus:
            for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
                # Lexical fallback intentionally includes comments; human review required.
                for rule in rules:
                    if re.search(rule['pattern-regex'], line):
                        findings.append(hint(rule, str(path.relative_to(root)), number, line, selected))
                        if len(findings) > 5000:
                            raise ValueError('Finding limit exceeded')
    return dict(engine=selected, diagnostic=diagnostic, findings=findings,
                repository='isolated-synthetic-fixtures' if fixture else manifest['repository'],
                commit='fixture-' + version if fixture else manifest['commit'],
                corpus_sha256=version, fixture=fixture)
