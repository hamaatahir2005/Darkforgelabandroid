# Evidence-first research procedure

## Scope and authorization

The authorized scope is public AOSP source, local synthetic components and supplied offline logs. No device connections, production probing, external target-service APIs, user data collection, exploit deployment or automatic Bug Hunters submission. The public GitHub source retrieval endpoint is the explicit exception needed for the requested public-source download and connected repository commit. Direct online acquisition requires `--online`.

## Hypothesis record

For every hint, capture: repository and exact commit, relative file/line, rule, snippet, suspected caller-controlled input, entry point, required permissions, expected invariant, a falsifiable hypothesis, potential impact *if* demonstrated, local evidence and a proposed fix. Rule metadata supplies starting hypotheses and recommendations; the researcher must establish facts from complete code paths.

All rule confidence values are fixed heuristic relevance scores, chosen to make broad matches visible: permission 0.35, export 0.45, deserialization 0.50, input bounds 0.40, sensitive logging 0.55. They are not calibrated probabilities. INFO/WARNING Semgrep labels indicate review priority, not vulnerability severity. CWE identifiers describe the weakness family to investigate and may change after root-cause analysis.

## Validation boundary

`validate` executes eight deterministic checks on bundled synthetic Python models: a deliberately missing permission enforcement model, its fixed counterpart, input length boundaries, structured schema validation, and constant safe logging. It does not emulate Binder, AIDL, Android identities, SELinux, AppOps or Android permission semantics. It cannot establish that any real AOSP hint is vulnerable. Static Java/XML samples are not compiled or executed.

Crash parsers extract signatures and context; they do not reproduce crashes. Sanitizer family CWE values are provisional. Logs can include sensitive information, so only parse synthetic or explicitly authorized, redacted files. Address normalization supports grouping crash signatures but is not root-cause duplicate detection.

For real independent validation, separately document an authorized isolated Android version/commit, complete build/runtime setup, repeatable minimal reproduction, expected vs actual security boundary behavior, and a regression test against a patch. This lab intentionally keeps AOSP findings unconfirmed until that separate work exists. Store external validation notes in a reviewed report; there is no misleading automatic “confirmed” flag.

## Patch and disclosure

Prefer changes that preserve intended permission contracts: enforce before side effects, deny on failure, use actual calling identity, constrain deserialization classes/inputs, check all bounds and avoid logging secrets. A generic recommendation is not a verified AOSP patch. Include regression evidence with any real patch and examine compatibility implications.

The [Google Bug Hunters template](../templates/google-bughunters.md) is a draft only. Verify current Android VRP eligibility, affected supported versions, scope and disclosure requirements manually. The generated draft explicitly records missing independent validation and unknown impact. No submission or messaging tool is called.
