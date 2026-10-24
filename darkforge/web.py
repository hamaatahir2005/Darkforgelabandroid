"""Local, read-only dashboard. No CDN, telemetry, scan endpoints or upload surface."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import secrets
import urllib.parse
from .db import Database
from .limits import job

PAGE = '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DarkForge-X Lab</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#e7efff;font:16px system-ui}header,main{max-width:1050px;margin:auto;padding:1rem}header{border-bottom:1px solid #334466}h1{font-size:1.8rem;color:#76e4cf}.notice{padding:1rem;background:#30291a;border:1px solid #8d7134;border-radius:12px}nav{display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0}button,input{font:inherit;padding:.75rem;border:1px solid #526780;border-radius:8px;background:#18243c;color:inherit;min-height:44px}button{cursor:pointer}input{width:100%}article{border:1px solid #334466;border-radius:12px;padding:1rem;margin:1rem 0;background:#121c30}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#0a1020;padding:.7rem}small{color:#b1c3db}label{display:block;margin:.5rem 0}.stats{display:flex;gap:1rem;flex-wrap:wrap}.badge{color:#ffd27a}#status{min-height:1.5rem}a{color:#76e4cf}@media(max-width:600px){header,main{padding:.8rem}h1{font-size:1.5rem}button{flex:1}}</style></head>
<body><header><h1>DarkForge-X</h1><p>Android OS Security Research Lab</p></header><main>
<div class="notice">Review hints only. No independently validated AOSP vulnerability. Synthetic test results do not validate Android behavior.</div>
<nav><button id="findings">Findings</button><button id="runs">Provenance</button><button id="evidence">Local evidence</button></nav>
<label for="filter">Filter findings by text or CWE</label><input id="filter" placeholder="CWE-862, permission, path…" autocomplete="off">
<form id="search"><label for="query">Search selected source code (literal text)</label><input id="query" maxlength="200" required placeholder="enforcePermission"><button>Search source</button></form>
<p id="status" role="status">Loading…</p><section id="results" aria-live="polite"></section>
<p><small>Read-only dashboard. Use the CLI to scan, review and generate HTML, JSON, Markdown and PDF reports. Source text is rendered as text, never HTML.</small></p></main><script>
const token=new URLSearchParams(location.hash.slice(1)).get('token')||'';
history.replaceState(null,'',location.pathname);
let data=null;
const out=document.getElementById('results'),status=document.getElementById('status');
function text(tag,value,parent=out){const el=document.createElement(tag);el.textContent=value;parent.appendChild(el);return el;}
async function api(path){const r=await fetch(path,{headers:{'Authorization':'Bearer '+token}});if(!r.ok)throw Error(await r.text());return await r.json();}
function findings(){out.replaceChildren();const q=document.getElementById('filter').value.toLowerCase();const items=data.findings.filter(f=>JSON.stringify(f).toLowerCase().includes(q));status.textContent=items.length+' review hints; confidence describes pattern relevance only';for(const f of items){const card=text('article','');text('h2','#'+f.id+' · '+f.title,card);text('p',f.status+' · '+f.cwe+' · confidence '+f.confidence+' · seen '+f.seen,card).className='badge';text('small',f.path+':'+f.line,card);text('pre',f.snippet,card);text('p','Hypothesis: '+f.hypothesis,card);text('p','Recommendation: '+f.recommendation,card);text('small',f.repository+' @ '+f.commit_sha,card);}}
function records(key){out.replaceChildren();status.textContent=data[key].length+' '+key+' records';for(const item of data[key])text('pre',JSON.stringify(item,null,2),text('article',''));}
document.getElementById('filter').oninput=()=>{if(data)findings();};
document.getElementById('findings').onclick=()=>{if(data)findings();};
document.getElementById('runs').onclick=()=>{if(data)records('runs');};
document.getElementById('evidence').onclick=()=>{if(data)records('evidence');};
document.getElementById('search').onsubmit=async e=>{e.preventDefault();try{const hits=await api('/api/search?q='+encodeURIComponent(document.getElementById('query').value));out.replaceChildren();status.textContent=hits.length+' matches (maximum 100)';for(const h of hits){const card=text('article','');text('small',h.path+':'+h.line,card);text('pre',h.text,card);}}catch(e){status.textContent=e.message;}};
api('/api/data').then(d=>{data=d;findings();}).catch(e=>status.textContent=e.message);
</script></body></html>'''


def handler(db_path, source_root, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Do not log authentication or source text.

        def send(self, code, value, content_type='application/json'):
            body = value.encode() if isinstance(value, str) else json.dumps(value).encode()
            self.send_response(code)
            self.send_header('Content-Type', content_type + '; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.connection.settimeout(5)
            parsed = urllib.parse.urlsplit(self.path)
            # Host validation helps prevent DNS rebinding to the loopback dashboard.
            expected_hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            if self.headers.get('Host') not in expected_hosts:
                self.send(403, {'error': 'Invalid Host; use a localhost tunnel'})
                return
            if parsed.path == '/':
                self.send(200, PAGE, 'text/html')
                return
            supplied = self.headers.get('Authorization', '')
            if not hmac.compare_digest(supplied.encode(), ('Bearer ' + token).encode()):
                self.send(401, {'error': 'Open the startup URL including its #token fragment'})
                return
            try:
                if parsed.path == '/api/data':
                    db = Database(db_path)
                    try:
                        self.send(200, dict(findings=db.list_findings(), runs=db.runs(), evidence=db.evidence()))
                    finally:
                        db.close()
                elif parsed.path == '/api/search':
                    query = urllib.parse.parse_qs(parsed.query).get('q', [''])[0]
                    self.send(200, job('search', dict(root=str(source_root), query=query), wall=10))
                else:
                    self.send(404, {'error': 'Not found'})
            except (ValueError, RuntimeError) as exc:
                self.send(400, {'error': str(exc)[:500]})
    return Handler


def serve(db_path, source_root, port=8765):
    token = secrets.token_urlsafe(32)
    server = HTTPServer(('127.0.0.1', port), handler(db_path, source_root, token))
    # Bound request headers/read time, including clients which never finish a request.
    original = server.get_request
    def bounded_request():
        sock, address = original()
        sock.settimeout(5)
        return sock, address
    server.get_request = bounded_request
    print(f'Local read-only dashboard: http://127.0.0.1:{server.server_port}/#token={token}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def export_dashboard(db_path, source_root, destination):
    """Offline interactive dashboard, for runtimes where all sockets are denied."""
    from .reports import payload
    from .source import files
    root = Path(source_root).resolve()
    index = []
    total_chars = 0
    for path in files(root):
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            total_chars += len(line)
            if len(index) >= 100000 or total_chars > 8 * 1024 * 1024:
                raise ValueError('Offline source index exceeds export budget')
            index.append(dict(path=str(path.relative_to(root)), line=number, text=line[:500]))
    dataset = json.dumps(dict(data=payload(db_path), index=index), ensure_ascii=True)
    # Prevent script termination or HTML parsing of imported source/evidence.
    dataset = dataset.replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    old = "async function api(path){const r=await fetch(path,{headers:{'Authorization':'Bearer '+token}});if(!r.ok)throw Error(await r.text());return await r.json();}"
    new = "const offline=" + dataset + "; async function api(path){if(path==='/api/data')return offline.data;const q=new URL(path,'https://offline.invalid').searchParams.get('q')||'';if(!q.trim())throw Error('Enter a search query');return offline.index.filter(h=>h.text.toLowerCase().includes(q.toLowerCase())).slice(0,100);}"
    page = PAGE.replace(old, new).replace('Read-only dashboard. Use the CLI', 'Offline read-only dashboard. Use the CLI')
    if page == PAGE:
        raise RuntimeError('Dashboard template mismatch')
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(page)
    return dict(path=str(path), mode='offline interactive HTML; no server or external requests', indexed_lines=len(index))
