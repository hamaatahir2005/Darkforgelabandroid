# Initial PermissionEnforcer source review

Baseline: `aosp-mirror/platform_frameworks_base` at `1cdfff555f4a21f71ccc978290e2e212e2f8b168`, file `core/java/android/os/PermissionEnforcer.java`. This mirror revision is dated 2025-03-27; it is not asserted to be the latest release. This document is a source review, not a vulnerability advisory.

## Observed code paths

The protected `checkPermission(permission, source)` delegates to `PermissionChecker.checkPermissionForDataDelivery`. The pid/uid overload compares the Context result with `PackageManager.PERMISSION_GRANTED` and returns grant or hard denial. The builtin scanner intentionally matches these method declarations and legitimate permission checks; some of its nine hits are expected false positives as vulnerability candidates.

`enforcePermission(permission, source)` checks the result and throws `SecurityException` on denial. The pid/uid overload takes the AppOps-dependent path via an `AttributionSource` or checks directly and throws on denial.

Both `enforcePermissionAllOf` variants inspect each permission and throw on denied results. Both `enforcePermissionAnyOf` variants return on a granted result and throw after the loop if no permission is granted. AppOps-related delegation appears in the pid/uid variants.

These observed checks contradict a blanket claim that the matched permission result is ignored. The scanner cannot reason about this; human review is necessary. All database hints remain `unconfirmed` by default.

## Hypotheses and missing evidence

1. **Could caller identity be confused at a call site?** This requires generated AIDL, service callers, Binder identity lifetime and PermissionChecker/AppOps behavior. They are outside the one-file snapshot. No affected path has been demonstrated.
2. **Could an empty all-of permission list allow unintended access?** The loop has no iterations for an empty list, which is also the ordinary logical contract of “all of zero conditions.” There is no evidence an attacker can influence an annotation-generated permission list or that the contract is wrong. Do not label this a vulnerability.
3. **Could denial be mishandled in a framework dependency?** Establishing this requires the exact dependencies and runtime evidence. The supplied Python models do not validate those Android behaviors.

Safe model tests demonstrate only that a deliberately faulty Python function accepts denied input and its fixed version rejects it. They illustrate a research technique and patch regression check. They do not confirm any of these AOSP hypotheses.

## Recommendations

No AOSP patch is justified from this source slice alone. If expanding research, add generated AIDL and one explicitly selected service caller at a pinned commit, inspect identity and permission contracts, then validate in a separately authorized isolated Android environment. Preserve explicit denial behavior and add caller-specific regression tests before proposing a real patch.

**Result: zero independently validated AOSP vulnerabilities. Nine builtin permission review hints on the pinned file.**
