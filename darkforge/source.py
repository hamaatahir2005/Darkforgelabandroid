"""Allowlisted, pinned public AOSP component acquisition and integrity checks."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import time
import sys
import urllib.request

_checkout = Path(__file__).resolve().parents[1]
PROJECT = _checkout if (_checkout / 'vendor/aosp/manifest.json').is_file() else Path(sys.prefix) / 'share/darkforge'
COMMIT = '1cdfff555f4a21f71ccc978290e2e212e2f8b168'
REPOSITORY = 'aosp-mirror/platform_frameworks_base'
COMPONENT = 'core/java/android/os/PermissionEnforcer.java'
MAX_BYTES = 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL = 32 * 1024 * 1024
EXTENSIONS = {'.java', '.kt', '.cpp', '.cc', '.c', '.h', '.aidl', '.xml', '.py', '.log', '.txt'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def relative_path(value):
    p = PurePosixPath(value)
    if not value or p.is_absolute() or '..' in p.parts or '\\' in value:
        raise ValueError('Expected a safe repository-relative path')
    return str(p)


def read_url(url):
    # Only public source-code endpoints, no target services or device APIs.
    if not url.startswith(('https://raw.githubusercontent.com/aosp-mirror/',
                           'https://api.github.com/repos/aosp-mirror/')):
        raise ValueError('Source host is not allowlisted')
    req = urllib.request.Request(url, headers={'User-Agent': 'DarkForge-X/0.1'})
    with urllib.request.urlopen(req, timeout=15) as response:
        if not response.url.startswith(('https://raw.githubusercontent.com/aosp-mirror/',
                                        'https://api.github.com/repos/aosp-mirror/')):
            raise ValueError('Unexpected source redirect')
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Source response exceeds 1 MiB')
    return data


def acquire(destination, *, offline=True, ref=COMMIT):
    """One-file component snapshot, not a full frameworks clone or build.

    Online refresh resolves a ref once, then downloads only by immutable SHA.
    Offline mode verifies the connector-captured snapshot against its manifest.
    """
    dest = Path(destination)
    if dest.exists() and any(dest.iterdir()):
        raise ValueError('Destination must be empty; preserve existing snapshots')
    if offline:
        manifest = json.loads((PROJECT / 'vendor/aosp/manifest.json').read_text())
        data = (PROJECT / 'vendor/aosp' / COMPONENT).read_bytes()
        entry = manifest['files'][0]
        if digest(data) != entry['sha256'] or git_blob(data) != entry['git_blob_sha']:
            raise ValueError('Bundled source integrity mismatch')
    else:
        if not re.fullmatch(r'[A-Za-z0-9._/-]{1,150}', ref) or '..' in ref:
            raise ValueError('Invalid public AOSP ref')
        if re.fullmatch('[0-9a-f]{40}', ref):
            commit = ref
        else:
            commit = json.loads(read_url(f'https://api.github.com/repos/{REPOSITORY}/commits/{ref}'))['sha']
        if not re.fullmatch('[0-9a-f]{40}', commit):
            raise ValueError('Invalid resolved commit')
        data = read_url(f'https://raw.githubusercontent.com/{REPOSITORY}/{commit}/{COMPONENT}')
        manifest = dict(repository=REPOSITORY, canonical_repository='https://android.googlesource.com/platform/frameworks/base',
                        component=COMPONENT, commit=commit, acquisition='public HTTPS pinned snapshot',
                        retrieved_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                        files=[dict(path=COMPONENT, sha256=digest(data), git_blob_sha=git_blob(data))])
    target = dest / COMPONENT
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def verify_snapshot(root):
    root = Path(root).resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    if not re.fullmatch('[0-9a-f]{40}', manifest['commit']):
        raise ValueError('Invalid commit')
    if not 1 <= len(manifest['files']) <= MAX_FILES:
        raise ValueError('Invalid manifest size')
    for entry in manifest['files']:
        path = root / relative_path(entry['path'])
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('Source symlink not permitted')
        if path.stat().st_size > MAX_BYTES:
            raise ValueError('Source file too large')
        data = path.read_bytes()
        if digest(data) != entry['sha256'] or git_blob(data) != entry['git_blob_sha']:
            raise ValueError('Source integrity mismatch: ' + entry['path'])
    actual = {str(p.relative_to(root)) for p in files(root)}
    expected = {f['path'] for f in manifest['files']}
    if actual != expected:
        raise ValueError('Snapshot has untracked or missing source files')
    return manifest


def files(root):
    root = Path(root).resolve()
    count = total = 0
    # No symlink traversal, cap all visited entries including non-source files.
    import os
    visited = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {'.git', '.venv', '__pycache__'}
                         and not (Path(parent) / d).is_symlink())
        visited += len(dirs) + len(names)
        if visited > 10000:
            raise ValueError('Directory entry limit exceeded')
        for name in sorted(names):
            path = Path(parent) / name
            if path.is_symlink() or path.suffix not in EXTENSIONS:
                continue
            size = path.stat().st_size
            if size > MAX_BYTES:
                raise ValueError('File exceeds 1 MiB: ' + str(path))
            total += size
            count += 1
            if count > MAX_FILES or total > MAX_TOTAL:
                raise ValueError('Source corpus limit exceeded')
            yield path


def search(root, query, limit=100):
    if not 1 <= len(query) <= 200:
        raise ValueError('Search query must contain 1–200 characters')
    root = Path(root).resolve()
    hits = []
    for path in files(root):
        for number, line in enumerate(path.read_text(errors='replace').splitlines(), 1):
            if query.casefold() in line.casefold():
                hits.append(dict(path=str(path.relative_to(root)), line=number, text=line[:500]))
                if len(hits) >= min(200, max(1, limit)):
                    return hits
    return hits
