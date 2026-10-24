# Observed Codex environment — 2026-10-24

The environment was inspected before implementation using the Cloud Environment runtime skill, its status tool and `/etc/codex/network-policy.json`. Observed status was running/current, HTTP policy unrestricted and enforced, VPN not configured, with no reported secret bindings or outbound identity aliases. No credentials or environment values were dumped.

Python 3.12.14, Git 2.52.0 and `pdftotext` are available. Semgrep and pytest are not available. Standard-library `unittest` is used. ReportLab happened to be importable, but exports use the tested dependency-free PDF writer so it is not required.

Direct `git clone` and AOSP `git ls-remote` failed immediately with `Failed to connect to proxy port 8080`. An attempted optional Semgrep pip installation with bounded timeout and no retries returned `No matching distribution found`. This establishes package unavailability through the observed source; it does not establish that Semgrep is unsupported on all Python 3.12/Linux systems. No proxy bypass, alternate identity, interactive login or unsupported native package installation was attempted.

Extra network permission calls did not complete and were aborted during the session. Work continued using supported connected GitHub tools for the public source snapshot and final repository write. The branch was resolved to an immutable commit before downloading the file; its exact Git blob SHA and SHA-256 are checked in the manifest.

Creating an IPv4 localhost socket raises `PermissionError: [Errno 1] Operation not permitted` in this executor. Therefore the live HTTP server cannot be demonstrated here. The full HTTP handler is exercised with in-memory request/response transport, and an offline interactive HTML export is the working alternative. On Linux where sockets are permitted, the additional real HTTP smoke test runs automatically. There is no claimed mobile browser screenshot or public URL.

All core commands ran in this environment, and generated PDFs were parsed with the installed `pdftotext`. See `evidence/test-results.txt`, `evidence/verification.json` and generated reports. Semgrep integration was tested with simulated tool output only, explicitly distinguished from executing Semgrep.
