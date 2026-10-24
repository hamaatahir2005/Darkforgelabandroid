# DarkForge-X Research Report

2026-10-24T09:53:04.707864+00:00

RESEARCH HINTS ONLY. No independently validated AOSP vulnerability. Confidence measures pattern relevance, not exploitability. Synthetic model results do not establish Android behavior.



Recorded analysis runs

Run 1: aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

Engine: builtin; fixture=False; 

Corpus SHA256: 0ac4dffc016c0a6ce4911927b87b28f5020cd10dae3d642d845340bfd1a8fec5

Run 2: aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

Engine: builtin; fixture=False; 

Corpus SHA256: 0ac4dffc016c0a6ce4911927b87b28f5020cd10dae3d642d845340bfd1a8fec5



Findings (all require human review)

#1 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:96

Evidence:     protected int checkPermission(@NonNull String permission, @NonNull AttributionSource source) {

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#2 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:103

Evidence:     protected int checkPermission(@NonNull String permission, int pid, int uid) {

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#3 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:104

Evidence:         if (mContext.checkPermission(permission, pid, uid) == PackageManager.PERMISSION_GRANTED) {

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#4 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:131

Evidence:         int result = checkPermission(permission, source);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#5 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:144

Evidence:         int result = checkPermission(permission, pid, uid);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#6 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:153

Evidence:             int result = checkPermission(permission, source);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#7 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:169

Evidence:             int result = checkPermission(permission, pid, uid);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#8 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:180

Evidence:             int result = checkPermission(permission, source);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



#9 Review permission check result and caller identity before privileged action

Status: unconfirmed; CWE-862; confidence=0.35

aosp-mirror/platform_frameworks_base @ 1cdfff555f4a21f71ccc978290e2e212e2f8b168

core/java/android/os/PermissionEnforcer.java:197

Evidence:             int result = checkPermission(permission, pid, uid);

Hypothesis: Could a denied result be ignored, or a caller identity be confused? Trace callers and all branches.

Patch recommendation: Enforce permission before side effects; reject denied callers and document identity boundaries.

Reviewer: 



Evidence records

synthetic-validation SHA256=43a61700ac4ccd91d7d32f672f496bf1884fb6679238a50d2bcec81da11d091e

{"checks": [{"name": "synthetic missing-enforcement model returns data for denied input", "passed": true}, {"name": "patched model denies unprivileged input", "passed": true}, {"name": "patched model accepts explicit permission", "passed": true}, {"name": "oversized input rejected", "passed": true}, {"name": "boundary input accepted", "passed": true}, {"name": "structured decoding rejects wrong schema", "passed": true}, {"name": "structured decoding accepts expected schema", "passed": true}, {"name": "safe logging excludes credential values", "passed": true}], "independently_validated_aosp": false, "passed": true, "sample_sha256": "c6bf7e83dd9d3fa3b07f7ba0b866d76370f678ced53937b9fd761681cf5f7601", "scope": "synthetic Python models only; NOT validation of an AOSP vulnerability"}

synthetic-logs SHA256=5211f4eaf875557f91858bcce0698280e533f9634d1fcfab0b683dc4d88a2ca1

{"events": [{"context": ["SYNTHETIC FIXTURE: contains no device or user data", "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345678", "    #0 0x1234 in lab_copy synthetic.cpp:12", "ERROR: HWAddressSanitizer: tag-mismatch on address 0x12345678", "synthetic.cpp:18: runtime error: signed integer overflow", "signal 11 (SIGSEGV), code 1, fault addr 0x12345678", "FATAL EXCEPTION: main"], "cwe": "CWE-119", "kind": "asan", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 2, "signature": "22c17900a4bcb2d6c62ad91e1007ecba5286769af7491d3d839665e7ae5a0a67", "status": "unconfirmed", "summary": "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345678"}, {"context": ["    #0 0x1234 in lab_copy synthetic.cpp:12", "ERROR: HWAddressSanitizer: tag-mismatch on address 0x12345678", "synthetic.cpp:18: runtime error: signed integer overflow", "signal 11 (SIGSEGV), code 1, fault addr 0x12345678", "FATAL EXCEPTION: main", "java.lang.IllegalArgumentException: synthetic fixture"], "cwe": "CWE-119", "kind": "hwasan", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 4, "signature": "7bd95cfb6b09424e03d1dde43149dea4a2bdfda341c43b92494c0ded49a3908d", "status": "unconfirmed", "summary": "ERROR: HWAddressSanitizer: tag-mismatch on address 0x12345678"}, {"context": ["ERROR: HWAddressSanitizer: tag-mismatch on address 0x12345678", "synthetic.cpp:18: runtime error: signed integer overflow", "signal 11 (SIGSEGV), code 1, fault addr 0x12345678", "FATAL EXCEPTION: main", "java.lang.IllegalArgumentException: synthetic fixture"], "cwe": "CWE-758", "kind": "ubsan", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 5, "signature": "0e56abb74b887f7efd95498ccd12523592b123cd384876bae9f03ff6b4407c11", "status": "unconfirmed", "summary": "synthetic.cpp:18: runtime error: signed integer overflow"}, {"context": ["synthetic.cpp:18: runtime error: signed integer overflow", "signal 11 (SIGSEGV), code 1, fault addr 0x12345678", "FATAL EXCEPTION: main", "java.lang.IllegalArgumentException: synthetic fixture"], "cwe": "unclassified", "kind": "android-native", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 6, "signature": "16afe8c46912a80968d93596a8d0f45d86230b54783283aee6a0e45c7f70fcae", "status": "unconfirmed", "summary": "signal 11 (SIGSEGV), code 1, fault addr 0x12345678"}, {"context": ["signal 11 (SIGSEGV), code 1, fault addr 0x12345678", "FATAL EXCEPTION: main", "java.lang.IllegalArgumentException: synthetic fixture"], "cwe": "unclassified", "kind": "android-java", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 7, "signature": "9b9538c2a9ec21b52bbc21ae36e9f8c07290f90846b999f5d90c9a83dd646475", "status": "unconfirmed", "summary": "FATAL EXCEPTION: main"}, {"context": ["FATAL EXCEPTION: main", "java.lang.IllegalArgumentException: synthetic fixture"], "cwe": "unclassified", "kind": "android-java", "limitation": "A crash signature does not establish root cause, reachability, or a vulnerability.", "line": 8, "signature": "4d4f73ac91bc7714d1311d23a4b63f68746ff388518c5903a265f22fdd1a7ae5", "status": "unconfirmed", "summary": "java.lang.IllegalArgumentException: synthetic fixture"}], "sha256": "dd28bd7f843b8e6a86bce49e79e3151e70a9c1806edb48bd146994ae16446bea", "truncated": false}
