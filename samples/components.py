"""Safe Python models. No Android runtime, real identities, devices or secrets."""
MAX_PAYLOAD = 1024


def vulnerable_permission_model(granted):
    # Deliberately faulty model: observes result without enforcement.
    bool(granted)
    return 'synthetic privileged result'


def fixed_permission_model(granted):
    if granted is not True:
        raise PermissionError('Denied')
    return 'synthetic privileged result'


def validate_payload(value):
    if not isinstance(value, bytes) or len(value) > MAX_PAYLOAD:
        raise ValueError('Expected at most 1024 bytes')
    return len(value)


def safe_decode(data):
    # Structured data only, no object construction or pickle.
    import json
    validate_payload(data)
    result = json.loads(data)
    if not isinstance(result, dict) or set(result) != {'name'} or not isinstance(result['name'], str):
        raise ValueError('Expected exactly one string name')
    if not 1 <= len(result['name']) <= 64:
        raise ValueError('Name length out of range')
    return result


def safe_log_event():
    return 'authentication attempted'  # no input can carry credentials into logs
