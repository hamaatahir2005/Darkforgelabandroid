import copy
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import HTTPServer
from unittest.mock import patch

from darkforge.source import PROJECT, COMPONENT, COMMIT, acquire, verify_snapshot, search, files, relative_path
from darkforge.scanner import scan, load_rules
from darkforge.db import Database
from darkforge.logs import parse_log
from darkforge.validation import validate
from darkforge.reports import generate, pdf_builtin
from darkforge.limits import job, run_process
from darkforge.web import handler


class LabTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / 'aosp'
        acquire(self.source)
        self.db = Database(self.root / 'lab.sqlite')

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_source_provenance_exact_blob(self):
        manifest = verify_snapshot(self.source)
        self.assertEqual(manifest['commit'], COMMIT)
        data = (self.source / COMPONENT).read_bytes()
        self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
                         '3cc6fb5ad0ef422241a31809dc0f526e953cb46d')

    def test_tamper_rejected(self):
        (self.source / COMPONENT).write_text('altered')
        with self.assertRaises(ValueError):
            scan(self.source)

    def test_extra_source_rejected(self):
        (self.source / 'unexpected.java').write_text('class Unexpected {}')
        with self.assertRaises(ValueError):
            verify_snapshot(self.source)

    def test_acquire_does_not_overwrite(self):
        with self.assertRaises(ValueError):
            acquire(self.source)

    def test_online_ref_resolution_and_hash(self):
        from darkforge.source import git_blob
        data = b'// isolated mocked public download\n'
        with patch('darkforge.source.read_url', side_effect=[json.dumps({'sha': COMMIT}).encode(), data]) as read:
            manifest = acquire(self.root / 'online', offline=False, ref='main')
        self.assertEqual(manifest['commit'], COMMIT)
        self.assertEqual(manifest['files'][0]['git_blob_sha'], git_blob(data))
        self.assertIn(COMMIT, read.call_args_list[1].args[0])
        self.assertEqual(verify_snapshot(self.root / 'online')['commit'], COMMIT)

    def test_path_traversal_and_symlink_rejected(self):
        for name in ['../outside', '/etc/passwd', 'x\\y']:
            with self.assertRaises(ValueError):
                relative_path(name)
        p = self.source / COMPONENT
        p.unlink()
        p.symlink_to(PROJECT / 'samples/ReviewTargets.java')
        with self.assertRaises(ValueError):
            verify_snapshot(self.source)

    def test_literal_search_and_locations(self):
        hits = search(self.source, 'enforcePermission')
        self.assertTrue(hits)
        self.assertTrue(all(h['path'] == COMPONENT and h['line'] > 0 for h in hits))
        self.assertEqual(search(self.source, '.*'), [])
        with self.assertRaises(ValueError):
            search(self.source, '')

    def test_file_size_limit(self):
        huge = self.root / 'huge'
        huge.mkdir()
        (huge / 'a.java').write_bytes(b'x' * (1024 * 1024 + 1))
        with self.assertRaises(ValueError):
            list(files(huge))

    def test_five_rule_categories_and_unconfirmed(self):
        result = scan(PROJECT / 'samples', engine='builtin', fixture=True)
        self.assertEqual({f['rule'] for f in result['findings']}, {r['id'] for r in load_rules()})
        self.assertTrue(all(f['status'] == 'unconfirmed' and 0 < f['confidence'] < 1 for f in result['findings']))
        self.assertEqual(result['repository'], 'isolated-synthetic-fixtures')

    def test_aosp_results_do_not_claim_vulnerabilities(self):
        result = scan(self.source, engine='builtin')
        self.assertTrue(result['findings'])
        self.assertEqual(result['commit'], COMMIT)
        self.assertTrue(all(f['status'] == 'unconfirmed' for f in result['findings']))

    @unittest.skipUnless(shutil.which('semgrep'), 'Semgrep is not installed; real engine integration not verified')
    def test_real_semgrep_when_available(self):
        result = scan(PROJECT / 'samples', engine='semgrep', fixture=True)
        self.assertEqual({f['rule'] for f in result['findings']}, {r['id'] for r in load_rules()})
        self.assertEqual(result['engine'], 'semgrep')

    def test_semgrep_missing_explicit_and_auto(self):
        with patch('darkforge.scanner.shutil.which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                scan(self.source, engine='semgrep')
            result = scan(self.source, engine='auto')
        self.assertEqual(result['engine'], 'builtin')
        self.assertIn('not installed', result['diagnostic'])

    def test_semgrep_adapter_parses_results_without_claiming_real_execution(self):
        fake = {'results': [{'check_id': 'rules.df-permission-check-review',
                            'path': str(self.source / COMPONENT), 'start': {'line': 110}}], 'errors': []}
        with patch('darkforge.scanner.shutil.which', return_value='/fake/semgrep'), \
             patch('darkforge.scanner.run_process', return_value=dict(returncode=0,timed_out=False,stdout=json.dumps(fake))) as run:
            result = scan(self.source, engine='semgrep')
        self.assertEqual(len(result['findings']), 1)
        self.assertIn('--metrics=off', run.call_args.args[0])

    def test_semgrep_errors_fail_closed(self):
        with patch('darkforge.scanner.shutil.which', return_value='/fake/semgrep'), \
             patch('darkforge.scanner.run_process', return_value=dict(returncode=0,timed_out=False,stdout='{"errors":["parse failed"]}')):
            with self.assertRaisesRegex(RuntimeError, 'incomplete'):
                scan(self.source, engine='semgrep')

    def test_dedup_preserves_occurrences_review_and_commit(self):
        result = scan(self.source, engine='builtin')
        self.db.record(result)
        first = self.db.list_findings()
        self.db.review(first[0]['id'], 'needs-review', 'Trace the caller identity before a conclusion')
        self.db.record(result)
        rows = self.db.list_findings()
        self.assertEqual(len(rows), len(first))
        self.assertTrue(all(r['seen'] == 2 for r in rows))
        self.assertEqual(rows[0]['status'], 'needs-review')
        newer = copy.deepcopy(result)
        newer['commit'] = 'a' * 40
        self.db.record(newer)
        self.assertEqual(len(self.db.list_findings()), 2 * len(first))
        self.assertEqual(len({f['line'] for f in first}), len(first))

    def test_confirmation_is_not_an_allowed_review_state(self):
        self.db.record(scan(self.source, engine='builtin'))
        with self.assertRaises(ValueError):
            self.db.review(1, 'confirmed', 'A lexical match is not validation')
        with self.assertRaises(ValueError):
            self.db.review(9999, 'rejected', 'not present')

    def test_all_log_formats(self):
        result = parse_log((PROJECT / 'samples/sanitizer.log').read_text())
        self.assertEqual({e['kind'] for e in result['events']}, {'asan','hwasan','ubsan','android-native','android-java'})
        self.assertTrue(all(e['status'] == 'unconfirmed' for e in result['events']))
        self.assertEqual(parse_log('normal event')['events'], [])
        with self.assertRaises(ValueError):
            parse_log('x' * (1024 * 1024 + 1))

    def test_crash_signature_normalizes_address(self):
        a = parse_log('ERROR: AddressSanitizer: heap-buffer-overflow 0x1234')['events'][0]
        b = parse_log('ERROR: AddressSanitizer: heap-buffer-overflow 0x9876')['events'][0]
        self.assertEqual(a['signature'], b['signature'])

    def test_local_models_are_scoped_and_pass(self):
        result = validate()
        self.assertTrue(result['passed'])
        self.assertFalse(result['independently_validated_aosp'])
        self.assertEqual(len(result['checks']), 8)

    def test_worker_search_and_validation(self):
        self.assertTrue(job('search', dict(root=str(self.source), query='SecurityException'), wall=10))
        self.assertTrue(job('validate', {}, wall=10)['passed'])

    def test_wall_timeout_kills_worker(self):
        result = run_process([sys.executable, '-c', 'import time; time.sleep(10)'], wall=0.1)
        self.assertTrue(result['timed_out'])
        self.assertNotEqual(result['returncode'], 0)

    def test_memory_limit_is_enforced(self):
        result = run_process([sys.executable, '-c', 'x=bytearray(512*1024*1024)'], memory_mb=96)
        self.assertNotEqual(result['returncode'], 0)
        self.assertIn('MemoryError', result['stderr'])

    def test_reports_evidence_escaping_and_pdf(self):
        self.db.record(scan(self.source, engine='builtin'))
        self.db.add_evidence('validation', validate())
        with self.db.conn:
            self.db.conn.execute('UPDATE findings SET snippet=? WHERE id=1', ('<script>alert(1)</script>',))
        dest = self.root / 'reports'
        result = generate(str(self.root / 'lab.sqlite'), str(dest))
        self.assertEqual(len(result['files']), 5)
        report = json.loads((dest / 'report.json').read_text())
        self.assertEqual(len(report['evidence']), 1)
        self.assertIn(COMMIT, (dest / 'report.md').read_text())
        self.assertNotIn('<script>alert', (dest / 'report.html').read_text())
        self.assertIn('&lt;script&gt;', (dest / 'report.html').read_text())
        self.assertTrue((dest / 'report.pdf').read_bytes().startswith(b'%PDF-1.4'))
        self.assertIn('UNCONFIRMED', (dest / 'bughunters-draft.md').read_text())
        if shutil.which('pdftotext'):
            result = run_process(['pdftotext', str(dest / 'report.pdf'), '-'], wall=10)
            self.assertEqual(result['returncode'], 0)
            self.assertIn('DarkForge-X', result['stdout'])
            self.assertIn(COMMIT, result['stdout'])

    def test_pdf_multiple_pages_and_literal_escaping(self):
        path = self.root / 'long.pdf'
        pdf_builtin(path, ['literal (parentheses) \\ backslash'] * 200)
        self.assertIn(b'/Count 4', path.read_bytes())
        if shutil.which('pdftotext'):
            result = run_process(['pdftotext', str(path), '-'], wall=10)
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['stdout'].count('literal (parentheses)'), 200)

    def test_offline_dashboard_embeds_safe_data_and_search(self):
        from darkforge.web import export_dashboard
        self.db.record(scan(self.source, engine='builtin'))
        self.db.add_evidence('test', {'text': '</script><img src=x onerror=alert(1)>'})
        destination = self.root / 'dashboard.html'
        result = export_dashboard(str(self.root / 'lab.sqlite'), self.source, destination)
        page = destination.read_text()
        self.assertIn('const offline=', page)
        self.assertNotIn("await fetch(", page)
        self.assertNotIn('</script><img', page)
        self.assertIn('\\u003c/script', page)
        self.assertGreater(result['indexed_lines'], 200)

    @unittest.skipUnless(shutil.which('node'), 'Node is optional; offline JS execution check unavailable')
    def test_offline_dashboard_javascript_search_and_filter(self):
        import re
        from darkforge.web import export_dashboard
        self.db.record(scan(self.source, engine='builtin'))
        destination = self.root / 'dashboard.html'
        export_dashboard(str(self.root / 'lab.sqlite'), self.source, destination)
        script = re.search(r'<script>(.*?)</script>', destination.read_text(), re.S).group(1)
        harness = r"""
const assert=require('node:assert/strict');
class Element { constructor(){this.children=[];this.value='';this.textContent='';} appendChild(x){this.children.push(x);} replaceChildren(){this.children=[];} }
const elements={};
global.document={getElementById:(id)=>elements[id]||(elements[id]=new Element()),createElement:()=>new Element()};
global.location={hash:'',pathname:'/'};global.history={replaceState:()=>{}};
global.fetch=()=>{throw Error('Offline dashboard attempted a network request');};
"""
        checks = r"""
setImmediate(async()=>{try{
assert.ok(data.findings.length>0);assert.equal(out.children.length,data.findings.length);
document.getElementById('filter').value='no-such-hint';findings();assert.equal(out.children.length,0);
document.getElementById('filter').value='';findings();assert.ok(out.children.length>0);
document.getElementById('query').value='enforcePermission';
await document.getElementById('search').onsubmit({preventDefault(){}});
assert.ok(out.children.length>0);assert.ok(status.textContent.includes('matches'));
console.log('Offline dashboard JS: load/filter/source search passed without network');
}catch(e){console.error(e);process.exitCode=1;}});
"""
        file = self.root / 'dashboard-check.cjs'
        file.write_text(harness + script + checks)
        result = run_process([shutil.which('node'), str(file)], wall=10)
        self.assertEqual(result['returncode'], 0, result['stderr'])
        self.assertIn('passed without network', result['stdout'])

    def test_http_protocol_without_socket(self):
        import io
        from types import SimpleNamespace
        self.db.record(scan(self.source, engine='builtin'))
        Handler = handler(str(self.root / 'lab.sqlite'), self.source, 'test-token')

        class MemorySocket:
            def __init__(self, raw):
                self.input = io.BytesIO(raw)
                self.output = bytearray()
            def makefile(self, *_):
                return self.input
            def sendall(self, data):
                self.output.extend(data)
            def settimeout(self, _):
                pass

        def request(path, authorization='', host='localhost:8765'):
            raw = (f'GET {path} HTTP/1.0\r\nHost: {host}\r\nAuthorization: {authorization}\r\n\r\n').encode()
            socket = MemorySocket(raw)
            Handler(socket, ('127.0.0.1', 12345), SimpleNamespace(server_port=8765))
            head, body = bytes(socket.output).split(b'\r\n\r\n', 1)
            return head, body

        head, body = request('/')
        self.assertIn(b'200 OK', head)
        self.assertIn(b'width=device-width', body)
        head, body = request('/api/data')
        self.assertIn(b'401 Unauthorized', head)
        head, body = request('/api/data', 'Bearer test-token')
        self.assertIn(b'200 OK', head)
        self.assertTrue(json.loads(body)['findings'])
        head, body = request('/api/search?q=enforcePermission', 'Bearer test-token')
        self.assertIn(b'200 OK', head)
        self.assertTrue(json.loads(body))
        head, body = request('/api/data', 'Bearer test-token', 'attacker.invalid')
        self.assertIn(b'403 Forbidden', head)

    def test_dashboard_auth_search_and_host_guard(self):
        self.db.record(scan(self.source, engine='builtin'))
        try:
            server = HTTPServer(('127.0.0.1', 0), handler(str(self.root / 'lab.sqlite'), self.source, 'test-token'))
        except PermissionError:
            self.skipTest('Environment denies socket creation; in-memory HTTP protocol tested separately')
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            client.request('GET', '/')
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertIn(b'width=device-width', response.read())
            client.request('GET', '/api/data')
            response = client.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
            headers = {'Authorization': 'Bearer test-token'}
            client.request('GET', '/api/data', headers=headers)
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read())['findings'])
            client.request('GET', '/api/search?q=enforcePermission', headers=headers)
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertTrue(json.loads(response.read()))
            client.request('GET', '/api/data', headers=headers | {'Host': 'attacker.invalid'})
            response = client.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            client.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
