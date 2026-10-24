#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m darkforge doctor
# Rerun without overwriting an existing snapshot; scan verifies integrity.
if [ ! -f work/aosp/manifest.json ]; then python3 -m darkforge acquire; fi
python3 -m darkforge scan work/aosp --engine builtin
python3 -m darkforge search work/aosp enforcePermission
python3 -m darkforge logs samples/sanitizer.log
python3 -m darkforge validate
python3 -m darkforge report
python3 -m darkforge dashboard
