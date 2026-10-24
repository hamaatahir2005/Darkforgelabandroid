# Phase-two validation plan — not executed

The current cloud executor has no adb, emulator, aidl or javac on PATH. No Android build/runtime, installed application, device or HAL was used. Source graphs and Python controls are not independent Android validation.

## Stage A: service control-flow tests in an isolated Android test runtime

Resolve the exact multi-repository build manifest first. Build the corresponding AIDL compiler and the selected generated Java Stubs; preserve compiler/source/output hashes. Inspect each helper and transaction case, not only AIDL annotations. Check that helpers call the intended PermissionEnforcer using actual Binder credentials and that service overrides invoke them before effects.

Use Android service unit/instrumentation tests with an explicitly controlled fake PermissionEnforcer and fake operation sink. This tests service control flow, not Android permission-database correctness.

| Entry | Negative expected | Positive expected | Actual |
| --- | --- | --- | --- |
| SerialService.getSerialPorts | Denial propagates; no port-list work | Return the configured synthetic virtual name | NOT RUN |
| SerialService.openSerialPort | Denial propagates; supplier count = 0 | Fake supplier count = 1; return a harmless null result | NOT RUN |
| ConsumerIrService.transmit | Denial propagates; fake HAL count = 0 | Valid small pattern reaches fake sink once | NOT RUN |
| ConsumerIrService.getCarrierFrequencies | Denial propagates; fake HAL count = 0 | Fake frequency data returned | NOT RUN |
| ConsumerIrService.hasIrEmitter | No permission required; capability boolean only | Same behavior; no transmission | NOT RUN |

For SerialService, mock the resource serial-port array to empty and register a `virtual:` test port through the trusted in-process test API with an inert counting supplier. Do not invoke Os.open. For ConsumerIrService the production constructor performs native/HAL initialization: use a reviewed test-only injection seam or an existing matching Android test harness to supply fake HAL behavior. Do not instantiate that production path in an uncontrolled test and do not call real IR hardware. No such seam/patch has been applied in this project.

Assert the original permission exception propagates, the caller identity at enforcement is recorded before any clearing, and denied calls cause no observable protected effect. Test direct in-process invocation separately from Binder transactions. A fake enforcer's decision does not prove actual Android permission resolution.

## Stage B: real Binder and Android permission resolution

Use a separately authorized disposable Android emulator/system image, with real Context/PermissionEnforcer and fake operation sinks. Run server and client in separate processes. Record build fingerprint, commit manifest, UID/PID, declared/granted permissions, helper invocation and fake-sink counts. Never use production devices or user data.

- SERIAL_PORT is `signature|privileged`: use an ordinary unprivileged test client for the negative case and an appropriately provisioned platform-signed/privileged test client in the isolated image for the positive case. Do not assume a normal runtime grant can provide this permission.
- TRANSMIT_IR is `normal`: use separate test APKs with and without the permission declaration. A client which requests and receives a normal permission is an intended authorized caller, not evidence of bypass. Do not rely on runtime dangerous-permission toggling for this normal permission.
- hasIrEmitter is intentionally permission-free. The expected result is capability information only.
- Exercise both AIDL HAL and native fallback branches through fake sinks after enforcement. Verify SecurityException is not swallowed; distinguish later RemoteException handling from permission denial.
- LocalServices add/remove methods are same-process Java object calls, not remote Binder entry points. Enumerate their consumers before asserting any untrusted reachability.

A two-process Binder test with a fake enforcer validates identity transport/control flow only. Only actual Android permission resolution against the correct callers validates the permission boundary.

## Evidence and decision

For every case store expected versus actual results, full pinned source/build provenance, redacted synthetic-only logs, UID/PID and sink counts. A crash, source pattern, successful fake model, or intentionally permitted request is not a vulnerability.

If an unauthorized caller reaches a protected sink, repeat independently, rule out a test-harness configuration error, identify the specific boundary violation, and test a minimal reviewed fix with regression evidence. Otherwise retain Unconfirmed or reject the hypothesis. There is no current basis for an AOSP security patch or Bug Hunters vulnerability submission.
