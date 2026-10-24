#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
# Timeout and resource limits are applied by the Python runner, not assumed shell tools.
python3 scripts/run_tests.py
