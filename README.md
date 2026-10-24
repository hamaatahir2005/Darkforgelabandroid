# DarkForge-X

A practical Python 3 Android source security research lab. Works offline with a pinned, real AOSP component; does not build Android, connect to devices, or submit vulnerability reports.

**No independently validated AOSP vulnerability is claimed.** Static matches are review hints. All imported findings start `unconfirmed`; synthetic validation never promotes them. Confidence describes pattern relevance, not exploitability or severity.

## Quick start from an Android-controlled cloud terminal

Requires Linux/POSIX and Python 3.11+; the core has no pip dependencies. Run from the repository directory:

```sh
python3 -m darkforge doctor
sh scripts/test.sh
sh scripts/demo.sh
```

The demo copies and verifies the bundled AOSP snapshot, scans it, searches its code, parses synthetic logs, runs eight safe local model checks, and generates reports under `work/reports/`.

Open **`work/reports/dashboard.html`** for the offline, mobile-friendly interactive dashboard. It contains findings, exact source provenance, local evidence, filtering, and source search. It uses no external resources or network requests. The committed [example dashboard](evidence/dashboard.html) can be downloaded and opened as an HTML file; GitHub's source view does not execute HTML.

For a runtime that allows localhost sockets:

```sh
python3 -m darkforge serve --source work/aosp --port 8765
```

Open the printed URL, including its `#token=...` fragment, through an authorized localhost tunnel. The server binds only to `127.0.0.1`, validates Host, requires a bearer token for APIs and exposes read-only operations. It has no upload, scan, report-submission or mutation endpoints. The current Codex shell **denies socket creation**, so use the offline dashboard here. No public deployment has been created.

## Actual environment results

- Python 3.12.14 and Git 2.52.0 available; POSIX resource limits work.
- Offline wheel build and installation into an isolated virtual environment also passed, including the installed console command run outside this checkout.
- Core scanner, source hash verification, SQLite deduplication, search, crash parsing, safe models, offline dashboard, HTML/JSON/Markdown/PDF exports work.
- Direct Git/HTTPS shell operations failed because the configured proxy was unreachable. The real AOSP file was fetched through the connected GitHub tool, at a resolved immutable commit, and its Git blob SHA verified locally.
- Semgrep is unavailable. A bounded pip install attempt found no available distribution through the configured package source. Real Semgrep execution was **not tested**; adapter behavior is covered with mocked output. Builtin lexical rules are the working fallback and are not equivalent to semantic analysis.
- Live localhost HTTP smoke test is skipped when socket creation is forbidden. In-memory HTTP requests test authentication, source search, response content, and Host validation.
- The dependency-free PDF writer works and generated PDFs were parsed with `pdftotext`. JSON and HTML preserve Unicode; PDF's built-in Latin-1 font substitutes unsupported glyphs.

See [execution evidence](evidence/verification.json), [environment limitations](docs/ENVIRONMENT.md), and [source review](docs/AOSP_REVIEW.md).

## Selected component and provenance

The initial target is Framework `core/java/android/os/PermissionEnforcer.java`, from `aosp-mirror/platform_frameworks_base`, the public GitHub mirror of `platform/frameworks/base`.

- Exact commit: `1cdfff555f4a21f71ccc978290e2e212e2f8b168`.
- Git blob: `3cc6fb5ad0ef422241a31809dc0f526e953cb46d`.
- Snapshot and SHA-256 manifest: [vendor/aosp](vendor/aosp/manifest.json).
- Mirror commit date is 2025-03-27. This is a reproducible research baseline, **not a claim of current release coverage**.

Only one source file is downloaded. Dependencies, generated AIDL, callers and Android runtime behavior are not included. This keeps the project small and avoids a full Android checkout/build. Original AOSP license headers are preserved; see [third-party notice](vendor/NOTICE.md).

## Commands

```sh
# Verified offline source acquisition; destination must be empty.
python3 -m darkforge acquire --destination work/aosp

# Explicitly opt into public source HTTPS when your runtime supports it.
# Ref is resolved once, then the file is fetched by immutable commit SHA.
python3 -m darkforge acquire --online --ref main --destination work/aosp-refresh

# Static analysis, exact manifest/commit verification, and SQLite persistence.
python3 -m darkforge scan work/aosp --engine builtin
python3 -m darkforge scan work/aosp --engine auto

# Optional Semgrep, when supported by the host package source.
python3 -m venv .venv
.venv/bin/python -m pip install 'semgrep>=1.100,<2'
PATH="$PWD/.venv/bin:$PATH" python3 -m darkforge scan work/aosp --engine semgrep

# Synthetic corpus is explicitly separated from AOSP in the database.
python3 -m darkforge scan samples --fixture --engine builtin

# Literal source search: suitable for selected Framework/System Service trees.
python3 -m darkforge search work/aosp checkPermission

# Only offline, locally supplied and appropriately redacted logs.
python3 -m darkforge logs samples/sanitizer.log
python3 -m darkforge validate

# Notes preserve evidence; static analysis cannot set status to confirmed.
python3 -m darkforge review 1 needs-review --note 'Trace callers and denied branches'
python3 -m darkforge report --destination work/reports
python3 -m darkforge dashboard --source work/aosp --destination work/reports/dashboard.html
```

Use global `--db PATH` **before** the subcommand to select a separate database. `python3 -m darkforge --help` lists commands. Local source without a verified manifest must use `scan --fixture`, which clearly labels it as non-AOSP. Search accepts bounded local trees independently of acquisition.

## Workflow

1. Acquire selected public source and record its commit plus byte hashes.
2. Scan verified source with builtin rules or the optional local Semgrep adapter.
3. Review the full function, generated code, callers, permission results and trust boundary.
4. Record a testable hypothesis; classify using CWE and the rule's transparent heuristic confidence.
5. Validate only in an explicitly authorized isolated environment. This project executes only its own safe Python sample models, never downloaded code or attacker-supplied programs.
6. Retain unverified hints as `unconfirmed`, or add `needs-review`/`rejected` with a review note. The lab does not expose a “confirmed vulnerability” action.
7. Export evidence and patch recommendations. Complete the Google Bug Hunters **draft** manually only after independent validation. No external report submission is implemented.

Read [architecture and limits](docs/ARCHITECTURE.md), [research methodology](docs/RESEARCH.md), and [testing guide](docs/TESTING.md). All five rule categories share one local JSON/Semgrep-compatible config: permission enforcement, exported interfaces, deserialization, input validation and sensitive logging. These broad lexical patterns intentionally trade precision for review coverage; they cannot prove missing checks, data flow or reachability.
