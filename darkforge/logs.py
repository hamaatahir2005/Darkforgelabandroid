"""Offline Android tombstone, ASan/HWASan/UBSan and Java exception hints."""
import hashlib
import re

PATTERNS = [
    ('asan', r'(?:ERROR: AddressSanitizer|AddressSanitizer:DEADLYSIGNAL).*', 'CWE-119'),
    ('hwasan', r'(?:ERROR: HWAddressSanitizer|HWAddressSanitizer:).*', 'CWE-119'),
    ('ubsan', r'(?:.*runtime error:.*|UndefinedBehaviorSanitizer:.*)', 'CWE-758'),
    ('android-native', r'(?:.*signal \d+ \(SIG[A-Z]+\).*|.*Abort message:.*)', 'unclassified'),
    ('android-java', r'(?:.*FATAL EXCEPTION:.*|.*(?:java|android)\.[\w.]+(?:Exception|Error):.*)', 'unclassified'),
]


def parse_log(text):
    if len(text.encode()) > 1024 * 1024:
        raise ValueError('Log exceeds 1 MiB')
    events = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        for kind, pattern, cwe in PATTERNS:
            if re.search(pattern, line):
                normalized = re.sub(r'0x[0-9a-fA-F]+', '<address>', line)
                events.append(dict(kind=kind, line=number, summary=line[:500], cwe=cwe,
                                   signature=hashlib.sha256((kind + normalized).encode()).hexdigest(),
                                   context=lines[max(0, number-2):min(len(lines), number+5)],
                                   status='unconfirmed',
                                   limitation='A crash signature does not establish root cause, reachability, or a vulnerability.'))
                if len(events) >= 1000:
                    return dict(events=events, truncated=True)
                break
    return dict(events=events, truncated=False, sha256=hashlib.sha256(text.encode()).hexdigest())
