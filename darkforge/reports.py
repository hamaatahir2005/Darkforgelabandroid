"""Export escaped HTML, JSON, Markdown and paginated PDF with no web requests."""
import html
import json
from pathlib import Path
import textwrap
from .db import Database, now

DISCLAIMER = ('RESEARCH HINTS ONLY. No independently validated AOSP vulnerability. '
              'Confidence measures pattern relevance, not exploitability. '
              'Synthetic model results do not establish Android behavior.')


def markdown_escape(value):
    return str(value).replace('`', '\\`').replace('<', '&lt;').replace('>', '&gt;').replace('\n', ' ')


def payload(db_path):
    db = Database(db_path)
    try:
        return dict(title='DarkForge-X Research Report', generated_at=now(), disclaimer=DISCLAIMER,
                    runs=db.runs(), findings=db.list_findings(), evidence=db.evidence())
    finally:
        db.close()


def plain_lines(data):
    lines = [data['title'], data['generated_at'], DISCLAIMER, '', 'Recorded analysis runs']
    for run in data['runs']:
        lines += [f"Run {run['id']}: {run['repository']} @ {run['commit_sha']}",
                  f"Engine: {run['engine']}; fixture={bool(run['fixture'])}; {run['diagnostic']}",
                  f"Corpus SHA256: {run['corpus_sha256']}"]
    lines += ['', 'Findings (all require human review)']
    for f in data['findings']:
        lines += [f"#{f['id']} {f['title']}", f"Status: {f['status']}; {f['cwe']}; confidence={f['confidence']}",
                  f"{f['repository']} @ {f['commit_sha']}", f"{f['path']}:{f['line']}",
                  f"Evidence: {f['snippet']}", f"Hypothesis: {f['hypothesis']}",
                  f"Patch recommendation: {f['recommendation']}", f"Reviewer: {f['review']}", '']
    lines += ['Evidence records']
    for e in data['evidence']:
        lines += [f"{e['kind']} SHA256={e['sha256']}", json.dumps(e['data'], sort_keys=True)]
    return lines


def pdf_builtin(path, lines):
    """Small dependency-free PDF 1.4 writer: fixed font, wrapped pages, escaped strings.

    Latin-1 fallback substitutes unsupported glyphs; JSON/HTML preserve Unicode.
    """
    wrapped = [part for line in lines for part in (textwrap.wrap(line, 95) or [''])]
    pages = [wrapped[i:i+54] for i in range(0, len(wrapped), 54)] or [[]]
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'',
               b'<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>']
    kids = []
    for page in pages:
        page_id = len(objects) + 1
        stream_id = page_id + 1
        kids.append(f'{page_id} 0 R')
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream_id} 0 R >>'.encode())
        commands = ['BT /F1 9 Tf 36 756 Td 13 TL']
        for line in page:
            escaped = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
            escaped = ''.join(c if ord(c) >= 32 else ' ' for c in escaped)
            commands.append(f'({escaped}) Tj T*')
        commands.append('ET')
        stream = '\n'.join(commands).encode('latin-1', 'replace')
        objects.append(f'<< /Length {len(stream)} >>\nstream\n'.encode() + stream + b'\nendstream')
    objects[1] = f'<< /Type /Pages /Count {len(pages)} /Kids [{" ".join(kids)}] >>'.encode()
    out = bytearray(b'%PDF-1.4\n%DarkForge\n')
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(f'{number} 0 obj\n'.encode() + obj + b'\nendobj\n')
    xref = len(out)
    out.extend(f'xref\n0 {len(objects)+1}\n0000000000 65535 f \n'.encode())
    for offset in offsets[1:]:
        out.extend(f'{offset:010d} 00000 n \n'.encode())
    out.extend(f'trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
    Path(path).write_bytes(out)


def bughunter(data):
    # Drafts only. Deliberately cannot submit to Google or infer severity.
    lines = ['# Google Bug Hunters / Android VRP draft', '', '**UNCONFIRMED — do not submit as a validated vulnerability.**',
             '', 'Program eligibility and current Android VRP requirements must be checked manually.',
             '', '## Summary', 'TODO: independently validated impact and affected supported versions.',
             '', '## Source provenance']
    for run in data['runs']:
        lines.append(f"- {markdown_escape(run['repository'])} @ {run['commit_sha']} (engine: {run['engine']})")
    lines += ['', '## Affected component and trust boundary', 'TODO: entry point, caller identity, permissions, supported Android version.',
              '', '## Reproduction', 'TODO: authorized isolated test environment, prerequisites, minimal safe steps, expected and actual results.',
              '', '## Independent validation', 'NOT PROVIDED for AOSP. Synthetic fixtures are not Android validation.',
              '', '## Evidence', 'See report.json for file, line, exact commit, content hashes and local evidence.',
              '', '## Security impact and severity', 'UNKNOWN. Explain demonstrated impact; do not infer severity from a pattern.',
              '', '## Root cause and patch recommendation']
    for f in data['findings']:
        lines.append(f"- Hint {f['id']} ({f['status']}, {f['cwe']}): {markdown_escape(f['recommendation'])}")
    lines += ['', '## Attachments and privacy review', 'TODO: minimal redacted logs, test hashes, patch and regression evidence. No user data.',
              '', '## Disclosure', 'Submit manually only after validation and program eligibility review; no automatic external submission.']
    return '\n'.join(lines) + '\n'


def generate(db_path, destination):
    data = payload(db_path)
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(data, indent=2, ensure_ascii=False)
    (dest / 'report.json').write_text(raw + '\n')
    lines = plain_lines(data)
    (dest / 'report.md').write_text('# DarkForge-X Research Report\n\n' + '\n\n'.join(markdown_escape(x) for x in lines[1:]) + '\n')
    body = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    body += '<title>DarkForge-X report</title><style>body{font:16px system-ui;max-width:70rem;margin:auto;padding:1rem;background:#101522;color:#e4e9f4}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
    body += '<h1>DarkForge-X Research Report</h1><pre>' + html.escape('\n'.join(lines)) + '</pre></html>'
    (dest / 'report.html').write_text(body)
    pdf_builtin(dest / 'report.pdf', lines)
    (dest / 'bughunters-draft.md').write_text(bughunter(data))
    return dict(files=[str(dest / f) for f in ['report.json', 'report.md', 'report.html', 'report.pdf', 'bughunters-draft.md']],
                pdf_engine='builtin PDF 1.4, Latin-1 font; Unicode preserved in JSON/HTML')
