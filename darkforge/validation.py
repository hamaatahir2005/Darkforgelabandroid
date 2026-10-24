"""Run only hardcoded safe local models. Never execute downloaded source."""
import hashlib
import importlib.util
from pathlib import Path
from .source import PROJECT


def validate():
    sample = PROJECT / 'samples/components.py'
    spec = importlib.util.spec_from_file_location('lab_models', sample)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = []

    def check(name, ok):
        checks.append(dict(name=name, passed=bool(ok)))

    def rejected(call, error):
        try:
            call()
        except error:
            return True
        return False

    check('synthetic missing-enforcement model returns data for denied input',
          module.vulnerable_permission_model(False) == 'synthetic privileged result')
    check('patched model denies unprivileged input',
          rejected(lambda: module.fixed_permission_model(False), PermissionError))
    check('patched model accepts explicit permission',
          module.fixed_permission_model(True) == 'synthetic privileged result')
    check('oversized input rejected', rejected(lambda: module.validate_payload(b'x' * 1025), ValueError))
    check('boundary input accepted', module.validate_payload(b'x' * 1024) == 1024)
    check('structured decoding rejects wrong schema',
          rejected(lambda: module.safe_decode(b'{"role":"admin"}'), ValueError))
    check('structured decoding accepts expected schema', module.safe_decode(b'{"name":"lab"}') == {'name': 'lab'})
    check('safe logging excludes credential values', module.safe_log_event() == 'authentication attempted')
    return dict(scope='synthetic Python models only; NOT validation of an AOSP vulnerability',
                independently_validated_aosp=False, sample_sha256=hashlib.sha256(sample.read_bytes()).hexdigest(),
                checks=checks, passed=all(c['passed'] for c in checks))
