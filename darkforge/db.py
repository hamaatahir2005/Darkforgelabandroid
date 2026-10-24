"""SQLite evidence store. Static and crash evidence never promotes a finding."""
import hashlib
import json
from pathlib import Path
import sqlite3
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=5)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript('''
        PRAGMA foreign_keys=ON;
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS runs(
          id INTEGER PRIMARY KEY, created TEXT NOT NULL, repository TEXT NOT NULL,
          commit_sha TEXT NOT NULL, engine TEXT NOT NULL, diagnostic TEXT,
          corpus_sha256 TEXT NOT NULL, fixture INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS findings(
          id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
          first_run INTEGER REFERENCES runs(id), last_run INTEGER REFERENCES runs(id),
          seen INTEGER NOT NULL DEFAULT 1, repository TEXT NOT NULL, commit_sha TEXT NOT NULL,
          rule TEXT NOT NULL, path TEXT NOT NULL, line INTEGER NOT NULL, snippet TEXT NOT NULL,
          cwe TEXT NOT NULL, confidence REAL NOT NULL, title TEXT NOT NULL,
          hypothesis TEXT NOT NULL, recommendation TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'unconfirmed'
            CHECK(status IN ('unconfirmed','rejected','needs-review')),
          review TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS evidence(
          id INTEGER PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL,
          sha256 TEXT NOT NULL, data TEXT NOT NULL);
        ''')

    def close(self):
        self.conn.close()

    def record(self, result):
        with self.conn:
            cur = self.conn.execute('INSERT INTO runs(created,repository,commit_sha,engine,diagnostic,corpus_sha256,fixture) VALUES(?,?,?,?,?,?,?)',
                                    (now(), result['repository'], result['commit'], result['engine'],
                                     result['diagnostic'], result['corpus_sha256'], result['fixture']))
            run_id = cur.lastrowid
            for f in result['findings']:
                # Keep separate occurrences; normalize whitespace without losing literals.
                key = [result['repository'], result['commit'], f['rule'], f['path'],
                       f['line'], ' '.join(f['snippet'].split())]
                fingerprint = hashlib.sha256(json.dumps(key).encode()).hexdigest()
                self.conn.execute('''INSERT INTO findings(fingerprint,first_run,last_run,repository,commit_sha,
                  rule,path,line,snippet,cwe,confidence,title,hypothesis,recommendation)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(fingerprint) DO UPDATE SET seen=seen+1,last_run=excluded.last_run''',
                                  (fingerprint, run_id, run_id, result['repository'], result['commit'],
                                   f['rule'], f['path'], f['line'], f['snippet'], f['cwe'], f['confidence'],
                                   f['title'], f['hypothesis'], f['recommendation']))
        return run_id

    def list_findings(self):
        return [dict(row) for row in self.conn.execute('SELECT * FROM findings ORDER BY id')]

    def runs(self):
        return [dict(row) for row in self.conn.execute('SELECT * FROM runs ORDER BY id')]

    def evidence(self):
        return [dict(row) | {'data': json.loads(row['data'])}
                for row in self.conn.execute('SELECT * FROM evidence ORDER BY id')]

    def add_evidence(self, kind, data):
        raw = json.dumps(data, sort_keys=True)
        with self.conn:
            self.conn.execute('INSERT INTO evidence(created,kind,sha256,data) VALUES(?,?,?,?)',
                              (now(), kind, hashlib.sha256(raw.encode()).hexdigest(), raw))

    def review(self, finding_id, status, note):
        if status not in {'unconfirmed', 'rejected', 'needs-review'} or not note.strip():
            raise ValueError('Review requires a note and a supported status; no automatic vulnerability confirmation')
        with self.conn:
            cursor = self.conn.execute('UPDATE findings SET status=?,review=? WHERE id=?',
                                       (status, note[:8000], finding_id))
            if not cursor.rowcount:
                raise ValueError('Unknown finding')
