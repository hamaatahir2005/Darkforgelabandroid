"""Regenerate the bounded source review and copy the requested root report."""
import json
from pathlib import Path
import shutil
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from darkforge.limits import job
from darkforge.source import PROJECT

result = job('callgraph', dict(root=str(PROJECT / 'vendor/phase2'), destination=str(PROJECT / 'evidence/phase2')))
shutil.copyfile(PROJECT / 'evidence/phase2/AOSP_CALL_GRAPH_REVIEW.md', PROJECT / 'AOSP_CALL_GRAPH_REVIEW.md')
print(json.dumps(result, indent=2))
