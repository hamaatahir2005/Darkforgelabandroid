# Automated verification

Run `sh scripts/test.sh` from any directory, or `python3 scripts/run_tests.py` at the root. The runner places the suite in a bounded process group with an overall 90-second wall limit. No pytest or external network access is needed.

Tests verify immutable source provenance/Git blob identity, tamper/missing/untracked source rejection, no snapshot overwrite, mocked online ref resolution, path and symlink handling, file size limits, literal search, all five rule categories, fixture/AOSP separation, Semgrep absence and simulated result/error handling, occurrence/commit-sensitive deduplication and note preservation, forbidden confirmation states, all five log families, normalized crash signatures, eight safe validation checks, bounded workers, enforced memory/wall limits, escaped report output, multipage valid PDFs, offline dashboard escaping/indexing, HTTP authentication/Host/search behavior, and offline JavaScript load/filter/search execution with Node when available. The Node harness uses a minimal DOM substitute and rejects network calls; it is not a mobile browser screenshot test.

The live HTTP test runs only when socket creation is permitted. It is explicitly skipped in this Codex executor; a separate test runs actual HTTP request parsing and response handling through an in-memory transport. No test claims a real Semgrep run or Android runtime validation.

Run `python3 scripts/acceptance.py` to regenerate committed demonstration evidence in `evidence/`. It uses a temporary fresh database and AOSP copy, preventing stale repeated demo runs from affecting counts. It creates reports and the offline interactive dashboard, stores the builtin scan JSON, tool availability, eight local model results, and parsed synthetic logs. The database itself is not committed. Every analysis step uses `limits.job`.

If Semgrep becomes available, run:

```sh
PATH="$PWD/.venv/bin:$PATH" python3 -m darkforge --db work/semgrep.sqlite scan samples --fixture --engine semgrep
PATH="$PWD/.venv/bin:$PATH" python3 -m darkforge --db work/semgrep.sqlite scan vendor/aosp --engine semgrep
```

A real optional integration test also runs automatically when `semgrep` is on PATH. It requires all five rule categories on the synthetic corpus. Semgrep errors fail the job instead of silently falling back or presenting a partial scan as complete.


## Phase-two checks

The suite also verifies pinned service/AIDL/compiler evidence; all required review fields; four explicit first-statement guards before selected sinks; the intentional RequiresNoPermission query; declaration/invocation separation excluding comments/strings; overloads; positive/negative source-order controls and conditional-guard rejection; exception/identity observations; every citation's exact line and excerpt; inferred generated edges; unexecuted Android runtime plans; same-process local routes; five expected/actual model cases with two deliberately faulty controls; tamper rejection; unexpected revision rejection; and bounded graph/report export.

`python3 scripts/phase2.py` reproduces `AOSP_CALL_GRAPH_REVIEW.md` and phase-two JSON/Mermaid evidence. The five Python model cases pass locally; all Android runtime cases explicitly remain NOT RUN. No emulator, AIDL compiler, Java compiler, device or external target service is used.
