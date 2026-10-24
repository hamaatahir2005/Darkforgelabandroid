# Architecture and resource boundaries

`cli` → `limits.job` → a fresh `worker` process → `source`, `scanner`, `logs`, `validation`, `reports` or offline dashboard export. SQLite writes occur after successful analysis; failed or partial scans do not insert successful runs. Search from the HTTP handler also uses a bounded worker.

| Module | Responsibility |
| --- | --- |
| source.py | One-file public AOSP snapshot acquisition; ref-to-SHA resolution; SHA-256 and Git blob verification; bounded corpus walk; literal search |
| scanner.py | Local rules, explicit builtin/Semgrep selection; fail on Semgrep errors; hypotheses and recommendations |
| db.py | Runs, findings, evidence, review notes; transactional deduplication |
| logs.py | ASan, HWASan, UBSan, Android native and Java signature parsing |
| validation.py | Eight hardcoded checks against safe Python models, never Android vulnerability validation |
| reports.py | Escaped HTML, JSON, Markdown, paginated PDF, Bug Hunters draft |
| web.py | Token-protected localhost read-only HTTP and server-free interactive HTML export |

## Limits

All CLI analysis/acquisition/export tasks run as child process groups with a 60-second wall timeout (40s acquisition, 15s CLI search, 10s dashboard search), 45 CPU seconds, 1536 MiB virtual address space, 16 MiB per output file, 128 open descriptors and 32 processes per UID where POSIX supports it. The test-suite runner uses a 90-second wall limit. Timeout kills the process group; leftover descendants are cleaned up after normal exit as well. CPU/file limits can cause a nonzero job failure before the wall limit.

Semgrep has an additional 40s wall bound, 5s per rule timeout, 512 MiB engine memory limit, one job and 1 MiB target size. Metrics and version checks are disabled. Only the bundled local config is used, never remote registry rules.

Corpus limits: 1 MiB/file, 2000 recognized source/log files, 32 MiB total, 10000 directory entries. Symlinks are not traversed. AOSP scan manifests reject altered/missing/untracked recognized source files. The offline index is limited to 100000 lines and 8 MiB source characters. Search is literal, case-insensitive, 1–200 characters and at most 100 results by default. Crash input is 1 MiB, with at most 1000 extracted events. Output volume is bounded by worker file limits.

These are resource controls, **not an untrusted-code sandbox**. The project never compiles or executes downloaded Android code. Use an actual container/VM and separate authorization before adding native exploit reproducers. Windows is unsupported because `resource` and POSIX process groups are required. The HTTP listener is a long-running service; each search is bounded and client reads have a five-second timeout.

## Database semantics

`runs` records repository, exact commit, corpus SHA-256, engine, fixture label and diagnostics. `findings` records path/line, snippet, rule, CWE, confidence, hypothesis, recommendation, review status and seen count. `evidence` stores hashed structured local validation or parsed-log results.

The duplicate fingerprint hashes repository + commit + rule + relative path + line + whitespace-normalized snippet. Rescanning the same occurrence increments `seen` and updates `last_run` while preserving review notes. Separate lines and commits remain separate. It deliberately does not merge semantically related findings across revisions or attempt root-cause deduplication. No vulnerability is confirmed by duplicate detection or a crash signature.

## Dashboard security and sharing

Live APIs require an unpredictable bearer token. The token is supplied in a URL fragment, removed from the visible URL by JavaScript, and never logged. The listener is loopback-only with a Host allowlist and no CORS. Responses disable caching, embedding and MIME sniffing. Source/evidence display uses `textContent`. There are no network CDNs, telemetry, mutation routes or submission APIs. The server is a small single-user tool, not a hardened multiuser hosting service.

Offline HTML embeds source and evidence, escapes script delimiters, and supports filtering/search entirely in the browser. Treat exported reports/dashboard as source-bearing artifacts; review content before sharing. No local credentials or environment variables are exported.
