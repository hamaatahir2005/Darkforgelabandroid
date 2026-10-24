"""Phase two: bounded source-correlated slices, not a whole-program Java analysis.

Observed calls and declarations are separated. Generated Binder dispatch/identity
edges are explicitly inferred from a separately pinned AIDL generator reference.
No analysis result or safe model is Android runtime vulnerability validation.
"""
import json
from pathlib import Path
import re
import shutil
from .source import verify_snapshot, digest

FRAMEWORK_COMMIT = '1cdfff555f4a21f71ccc978290e2e212e2f8b168'
GENERATOR_COMMIT = 'a73091e714248afbf28a6d2ec3226d756288cc75'
SERIAL = 'services/core/java/com/android/server/SerialService.java'
IR = 'services/core/java/com/android/server/ConsumerIrService.java'
ENFORCER = 'core/java/android/os/PermissionEnforcer.java'


def mask_java(text):
    """Mask comments/strings without changing offsets, braces or line numbers."""
    pattern = r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text, flags=re.S)


def methods(text):
    """Recognize ordinary Java method bodies in this source slice, not all Java.

    Some simple constructor bodies are also recognized. Abstract methods, dynamic
    dispatch/reflection and compiler-generated code are not resolved. Signatures and calls retain source offsets for audit.
    """
    code = mask_java(text)
    pattern = re.compile(r'(?m)^[ \t]*(?:(?:public|protected|private|static|final|synchronized|native|abstract|default)\s+)*'
                         r'(?:@[\w.]+\s+)*[\w.$<>?\[\], ]+?\s+(?P<name>[A-Za-z_$][\w$]*)\s*'
                         r'\((?P<params>[^{};]*?)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{')
    results = []
    for m in pattern.finditer(code):
        if m['name'] in {'if', 'for', 'while', 'switch', 'catch', 'synchronized'}:
            continue
        opening = m.end() - 1
        depth, end = 1, opening + 1
        while end < len(code) and depth:
            depth += (code[end] == '{') - (code[end] == '}')
            end += 1
        if depth:
            raise ValueError('Unbalanced method body')
        results.append(dict(name=m['name'], start=m.start(), name_start=m.start('name'),
                            body_start=opening+1, end=end, params=m['params'],
                            line=text.count('\n', 0, m.start('name'))+1))
    return results


def method(text, name, params=None):
    found = [m for m in methods(text) if m['name'] == name and (params is None or params in m['params'])]
    if len(found) != 1:
        raise ValueError(f'Ambiguous/missing method: {name}, matches={len(found)}')
    return found[0]


def calls(text, span):
    code = mask_java(text)
    output = []
    for m in re.finditer(r'(?<![\w$])(?:(?P<receiver>[A-Za-z_$][\w$]*)\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(',
                         code[span['body_start']:span['end']-1]):
        if m['name'] in {'if', 'for', 'while', 'switch', 'catch', 'synchronized', 'new'}:
            continue
        start = span['body_start'] + m.start()
        output.append(dict(name=m['name'], receiver=m['receiver'], offset=start,
                           line=text.count('\n', 0, start)+1))
    return output


def classify_permission_matches(text):
    declarations = {m['name_start'] for m in methods(text) if m['name'] == 'checkPermission'}
    code = mask_java(text)
    output = []
    for m in re.finditer(r'\bcheckPermission\s*\(', code):
        line = text.count('\n', 0, m.start())+1
        output.append(dict(line=line, kind='declaration' if m.start() in declarations else 'invocation',
                           snippet=text.splitlines()[line-1].strip(), status='unconfirmed'))
    return output


class Corpus:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.manifests = {}
        self.cache = {}
        for group, expected in [('frameworks', FRAMEWORK_COMMIT), ('aidl', GENERATOR_COMMIT)]:
            if not (self.root / group / 'manifest.json').is_file():
                raise ValueError('Phase-two corpus unavailable: use the checkout or pass --source /path/to/vendor/phase2')
            manifest = verify_snapshot(self.root / group)
            if manifest['commit'] != expected:
                raise ValueError('Phase-two baseline mismatch: ' + group)
            self.manifests[group] = manifest

    def text(self, path, group='frameworks'):
        key = (group, path)
        if path not in {e['path'] for e in self.manifests[group]['files']}:
            raise ValueError('Untracked evidence file: ' + path)
        if key not in self.cache:
            self.cache[key] = (self.root / group / path).read_text()
        return self.cache[key]

    def cite(self, path, needle, *, group='frameworks', span=None):
        text = self.text(path, group)
        start, end = (span['body_start'], span['end']) if span else (0, len(text))
        positions = [m.start() + start for m in re.finditer(re.escape(needle), text[start:end])]
        if len(positions) != 1:
            raise ValueError(f'Citation must resolve exactly once: {path}: {needle!r} ({len(positions)})')
        line = text.count('\n', 0, positions[0])+1
        manifest = self.manifests[group]
        return dict(repository=manifest['repository'], commit=manifest['commit'], path=path,
                    line=line, excerpt=text.splitlines()[line-1].strip(),
                    url=f"https://github.com/{manifest['repository']}/blob/{manifest['commit']}/{path}#L{line}")

    def declaration(self, path, span):
        manifest = self.manifests['frameworks']
        return dict(repository=manifest['repository'], commit=manifest['commit'], path=path,
                    line=span['line'], excerpt=self.text(path).splitlines()[span['line']-1].strip(),
                    url=f"https://github.com/{manifest['repository']}/blob/{manifest['commit']}/{path}#L{span['line']}")


SPECS = [
    dict(service='SerialService', interface='ISerialManager', client='SerialManager', path=SERIAL,
         name='getSerialPorts', params='', permission='SERIAL_PORT', operations=['ports.add(path)']),
    dict(service='SerialService', interface='ISerialManager', client='SerialManager', path=SERIAL,
         name='openSerialPort', permission='SERIAL_PORT', operations=['supplier.get()']),
    dict(service='ConsumerIrService', interface='IConsumerIrService', client='ConsumerIrManager', path=IR,
         name='transmit', permission='TRANSMIT_IR', operations=['mAidlService.transmit(', 'halTransmit(carrierFrequency, pattern)']),
    dict(service='ConsumerIrService', interface='IConsumerIrService', client='ConsumerIrManager', path=IR,
         name='getCarrierFrequencies', permission='TRANSMIT_IR', operations=['mAidlService.getCarrierFreqs()', 'halGetCarrierFrequencies()']),
    dict(service='ConsumerIrService', interface='IConsumerIrService', client='ConsumerIrManager', path=IR,
         name='hasIrEmitter', permission=None, operations=['return mHasNativeHal;']),
]


def order_check(text, span, helper_name, operation_names):
    """Textual order + straight-line first-statement check, not CFG dominance."""
    body = mask_java(text)[span['body_start']:span['end']-1]
    invocation = re.match(r'\s*super\.' + re.escape(helper_name) + r'\s*\(\s*\)\s*;', body)
    all_calls = calls(text, span)
    helper_calls = [c for c in all_calls if c['receiver'] == 'super' and c['name'] == helper_name]
    ops = [c for c in all_calls if c['name'] in operation_names]
    return dict(helper_is_first_statement=bool(invocation), helper_invocations=len(helper_calls),
                protected_calls=len(ops), helper_before_all_protected_calls=bool(helper_calls and ops)
                and all(helper_calls[0]['offset'] < op['offset'] for op in ops),
                limitation='Source order in selected method only; not a whole-program control-flow dominance proof')


def safe_model_validation():
    """Hardcoded model of ordering/identity only. Does not invoke Android or source."""
    checks = []

    def run(granted, *, clear_first=False, swallow_denial=False, capability_query=False):
        events = []
        uid = 20001
        try:
            if capability_query:
                return dict(outcome='capability', effects=[], uid_checked=None)
            if clear_first:
                uid = 1000
                events.append('identity-cleared')
            events.append(f'check-uid:{uid}')
            allowed = uid == 1000 or granted
            if not allowed:
                try:
                    raise PermissionError('denied')
                except PermissionError:
                    if not swallow_denial:
                        raise
            events.append('synthetic-operation')
            return dict(outcome='allowed', effects=events, uid_checked=uid)
        except PermissionError:
            return dict(outcome='denied', effects=events, uid_checked=uid)

    cases = [
        ('negative: denied caller has zero protected operations', dict(granted=False), 'denied', 0, 20001),
        ('positive: permitted caller reaches one synthetic operation', dict(granted=True), 'allowed', 1, 20001),
        ('mutation control: identity clear before check is detected', dict(granted=False, clear_first=True), 'allowed', 1, 1000),
        ('mutation control: swallowed denial is detected', dict(granted=False, swallow_denial=True), 'allowed', 1, 20001),
        ('capability query intentionally has no permission check', dict(granted=False, capability_query=True), 'capability', 0, None),
    ]
    for label, args, outcome, effects, uid in cases:
        actual = run(**args)
        expected = dict(outcome=outcome, protected_operation_count=effects, uid_checked=uid)
        observed = dict(outcome=actual['outcome'], protected_operation_count=actual['effects'].count('synthetic-operation'), uid_checked=actual['uid_checked'])
        checks.append(dict(name=label, expected=expected, actual=observed, passed=expected == observed))
    return dict(scope='safe local Python model only; mutations are test controls, not AOSP behavior',
                checks=checks, passed=all(c['passed'] for c in checks),
                android_runtime_executed=False, vulnerability_verified=False)


def analyze(root):
    corpus = Corpus(root)
    generator = 'generate_java_binder.cpp'
    generator_refs = [corpus.cite(generator, needle, group='aidl') for needle in [
        'string Credentials() const', 'mEnforcer.enforcePermission(',
        'this(android.os.PermissionEnforcer.fromContext(', '// the real call',
        'auto realCall = std::make_shared<MethodCall>(THIS_VALUE, method.GetName())']]
    results, edges = [], []
    for spec in SPECS:
        path, name = spec['path'], spec['name']
        text = corpus.text(path)
        if name == 'getSerialPorts':
            span = next(m for m in methods(text) if m['name'] == name and not m['params'].strip())
        else:
            span = method(text, name)
        aidl_path = f"core/java/android/hardware/{spec['interface']}.aidl"
        client_path = f"core/java/android/hardware/{spec['client']}.java"
        aidl = corpus.cite(aidl_path, name + '(')
        client = corpus.cite(client_path, 'mService.' + name + '(')
        entry = corpus.declaration(path, span)
        operations = [corpus.cite(path, op, span=span) for op in spec['operations']]
        helper_name = name + '_enforcePermission'
        guard = corpus.cite(path, 'super.' + helper_name + '()', span=span) if spec['permission'] else None
        op_names = ['add'] if name == 'getSerialPorts' else ['get'] if name == 'openSerialPort' else ['transmit', 'halTransmit'] if name == 'transmit' else ['getCarrierFreqs', 'halGetCarrierFrequencies']
        order = order_check(text, span, helper_name, op_names) if guard else None
        if spec['permission']:
            aidl_annotation = corpus.cite(aidl_path, f'@EnforcePermission("{spec["permission"]}")',
                                          span=dict(body_start=corpus.text(aidl_path).rfind(';', 0, corpus.text(aidl_path).index(name + '('))+1,
                                                    end=corpus.text(aidl_path).index(name + '(')))
        else:
            aidl_annotation = corpus.cite(aidl_path, '@RequiresNoPermission')
        method_body = mask_java(text)[span['body_start']:span['end']]
        catches = re.findall(r'\bcatch\s*\(\s*([\w.]+)', method_body)
        identity_calls = [c for c in calls(text, span) if c['name'] in {'clearCallingIdentity', 'restoreCallingIdentity', 'withCleanCallingIdentity'}]
        permission_ref = corpus.cite('core/res/AndroidManifest.xml', 'android:name="android.permission.' + spec['permission'] + '"') if spec['permission'] else None
        checks = dict(
            permission_before_operation=order,
            caller_identity='Expected generated helper reads Binder getCallingPid()/getCallingUid(); not an observed runtime identity' if guard else 'No caller-dependent access in this capability-query body',
            identity_management=dict(observed_clear_or_restore_calls=identity_calls, conclusion='No explicit identity transition in this selected method body'),
            exception_handling=dict(catch_types=catches, conclusion='No catch around the initial permission helper; IR RemoteException catches surround later HAL calls only' if guard else 'No catch in capability query'),
            permission_suitability=('SERIAL_PORT is signature|privileged and matches port access' if spec['permission']=='SERIAL_PORT' else 'TRANSMIT_IR is normal and matches IR use; normal protection is not a bypass' if guard else 'AIDL and implementation explicitly mark RequiresNoPermission'),
            alternate_routes='Direct Java calls to the same override still execute its explicit helper. LocalServices mutation API is analyzed separately. Uninspected callers are not excluded.' if path==SERIAL else 'AIDL HAL and native fallback occur after the helper. No alternate external route established within this slice; HAL/runtime policy outside scope.')
        result = dict(id=f"{spec['service']}.{name}", service_name=spec['service'], entry_point=spec['interface']+'.'+name,
                      caller_identity=checks['caller_identity'], required_permission='android.permission.'+spec['permission'] if guard else 'None: explicitly @RequiresNoPermission',
                      enforcement_location=guard, protected_operation=spec['operations'], source_file_and_line=entry,
                      aidl_commit=FRAMEWORK_COMMIT, aosp_commit=FRAMEWORK_COMMIT,
                      confidence_level=dict(observed_source='high', generated_dispatch_and_identity='medium; inferred, compiler revision not build-manifest matched', vulnerability='not assessed as established'),
                      validation_status='Unconfirmed — Android runtime/emulator unavailable; source observations only',
                      recommended_next_step='Generate the actual Stub from a resolved build manifest, then run authorized in-process Binder deny/allow tests with a fake sink; no serial/IR hardware calls.',
                      evidence=[aidl_annotation, aidl, client, entry]+([guard, permission_ref] if guard else [])+operations,
                      security_analysis=checks,
                      runtime_test_cases=[dict(case='negative: caller without required permission', expected='SecurityException and zero fake-sink operations', actual='NOT RUN', status='unconfirmed'),
                                          dict(case='positive: authorized caller', expected='Expected fake-sink operation/return, with Binder UID/PID recorded', actual='NOT RUN', status='unconfirmed')] if guard else
                                         [dict(case='capability query without permission', expected='Boolean capability only, no HAL mutation', actual='NOT RUN', status='unconfirmed')])
        results.append(result)
        method_node = spec['service']+'.'+name
        edges += [dict(source=spec['client']+'.'+name, target=spec['interface']+'.'+name, kind='observed-client-call', evidence=[client]),
                  dict(source=spec['interface']+'.'+name, target=method_node, kind='inferred-generated-binder-dispatch', evidence=[aidl, entry, generator_refs[3], generator_refs[4]])]
        if guard:
            edges += [dict(source=method_node, target=spec['interface']+'.Stub.'+helper_name,
                           kind='observed-explicit-helper-call', evidence=[guard]),
                      dict(source=spec['interface']+'.Stub.'+helper_name, target='PermissionEnforcer.enforcePermission',
                           kind='inferred-generated-permission-helper', evidence=[aidl_annotation, generator_refs[0], generator_refs[1]])]
        for op in operations:
            edges.append(dict(source=method_node, target=op['excerpt'], kind='observed-operation', evidence=[op]))
    local = []
    for name, operation in [('addVirtualSerialPortForTest','mSerialPorts.put(name, supplier)'), ('removeVirtualSerialPortForTest','mSerialPorts.remove(name)')]:
        text = corpus.text(SERIAL)
        span = method(text, name)
        evidence = [corpus.declaration(SERIAL, span), corpus.cite(SERIAL, operation, span=span),
                    corpus.cite(SERIAL,'publishLocalService(SerialManagerInternal.class, mService.mInternal)'),
                    corpus.cite('core/java/com/android/server/LocalServices.java', 'are not Binder objects and are only available in the same process.')]
        local.append(dict(id='SerialService.local.'+name, service_name='SerialService', entry_point='SerialManagerInternal.'+name,
                          caller_identity='Same-process LocalServices object reference; not an exported AIDL method',
                          required_permission='No Binder permission guard here; local in-process API', enforcement_location=None,
                          protected_operation=operation, source_file_and_line=evidence[0], aosp_commit=FRAMEWORK_COMMIT,
                          confidence_level=dict(observed_source='high', external_reachability='unconfirmed; none demonstrated'),
                          validation_status='Unconfirmed — no Android runtime test; not evidence of a bypass',
                          recommended_next_step='Enumerate LocalServices consumers in a separately expanded pinned slice; test with trusted fake suppliers only.',
                          evidence=evidence))
        edges.append(dict(source='SerialService.Lifecycle.onStart', target='SerialManagerInternal.'+name,
                          kind='observed-local-registration-and-interface; not Binder dispatch', evidence=evidence))
    supporting = dict(
        explicit_enforcer_injection=corpus.cite(SERIAL,'super(PermissionEnforcer.fromContext(context))'),
        serial_supplier_to_try_open=corpus.cite(SERIAL,'return tryOpen(serialPort)'),
        serial_native_open=corpus.cite(SERIAL,'FileDescriptor fd = Os.open('),
        serial_open_error_catch=corpus.cite(SERIAL,'catch (ErrnoException e)'),
        serial_service_registration=corpus.cite(SERIAL,'publishBinderService(Context.SERIAL_SERVICE, mService)'),
        serial_systemserver_start=corpus.cite('services/java/com/android/server/SystemServer.java','mSystemServiceManager.startService(SerialService.Lifecycle.class)'),
        ir_systemserver_registration=corpus.cite('services/java/com/android/server/SystemServer.java','ServiceManager.addService(Context.CONSUMER_IR_SERVICE, consumerIr)'),
        binder_uid_contract=corpus.cite('core/java/android/os/Binder.java','public static final native int getCallingUid()'),
        binder_pid_contract=corpus.cite('core/java/android/os/Binder.java','public static final native int getCallingPid()'),
        enforcer_appops_delegation=corpus.cite(ENFORCER,'if (permissionToOpCode(permission) != AppOpsManager.OP_NONE)',span=method(corpus.text(ENFORCER),'enforcePermission',params='int pid')),
        enforcer_denial=corpus.cite(ENFORCER,'int result = checkPermission(permission, pid, uid);',span=method(corpus.text(ENFORCER),'enforcePermission',params='int pid')))
    edges += [dict(source='return supplier.get();', target='tryOpen(serialPort) [configured supplier only; virtual target unresolved]',
                   kind='observed-configured-supplier-lambda', evidence=[supporting['serial_supplier_to_try_open']]),
              dict(source='tryOpen(serialPort) [configured supplier only; virtual target unresolved]', target='Os.open(path, O_RDWR | O_NOCTTY)',
                   kind='observed-native-open-call', evidence=[supporting['serial_native_open']])]
    classifications = classify_permission_matches(corpus.text(ENFORCER))
    return dict(schema_version=1, scope='Two selected services; five Binder interface methods and two local methods. Not exhaustive AOSP discovery.',
                frameworks_commit=FRAMEWORK_COMMIT, generator_reference_commit=GENERATOR_COMMIT,
                generator_reference_limitation='Historical AOSP compiler source is separately pinned; NOT proven to be the exact compiler of the frameworks build. Generated Stub files absent.',
                manifests=corpus.manifests, services=results, local_routes=local, graph_edges=edges,
                supporting_evidence=supporting, generator_evidence=generator_refs,
                phase_one_reclassification=classifications,
                validation=safe_model_validation(), environment_tools={name:shutil.which(name) for name in ['adb','emulator','aidl','javac']},
                android_runtime_validation='NOT RUN', independently_validated_vulnerabilities=0,
                limitations=['Lexical method/call extraction and manually selected sinks are not a general Java call graph or CFG.',
                             'No reflection, polymorphic resolution, JNI/HAL internals, complete LocalServices callers, SELinux or build artifacts analyzed. PermissionChecker/AppOps behavior beyond the enforcer delegation is not audited.',
                             'Source order and absence of local catches do not prove whole-program safety.',
                             'No Android runtime, emulator, generated Stub build or production device was used.'])


def markdown_ref(e):
    return f"[{e['path']}:{e['line']}]({e['url']})"


def render_report(data):
    lines = ['# AOSP Call Graph Review — DarkForge-X Phase Two', '',
             '**Source-backed observations, not confirmed vulnerabilities. Zero independently validated permission bypasses.**', '',
             'کورتەی ئەنجام: دوو Service، پێنج Binder entry point و دوو local method شیکرانەوە. چوار entry point ـی پارێزراو helper ـی permission پێش کردارەکە بانگ دەکەن. هیچ Permission Bypass ـێک پشتڕاست نەکراوەتەوە؛ تاقیکردنەوەی Android Runtime جێبەجێ نەکراوە.', '',
             '## Scope and provenance', '',
             'Phase one was read first: its nine PermissionEnforcer pattern hits were not vulnerabilities. This phase selects two small services, five Binder interface methods and two same-process local methods. Discovery is bounded, not an exhaustive AOSP caller inventory. GitHub indexed search returned no results; files were discovered/fetched by repository paths at immutable revisions.', '',
             f"Frameworks baseline: `{data['frameworks_commit']}` (`aosp-mirror/platform_frameworks_base`).", '',
             f"AIDL generator reference: `{data['generator_reference_commit']}` (`aosp-mirror-neo/platform_system_tools_aidl`). Chosen as a historical revision preceding the frameworks commit. **This is not a resolved multi-repository build manifest.** Compiler-generated dispatch and helper identity edges are inferred; no exact generated Stub artifact has been built or inspected.", '',
             'Every vendored byte is verified against Git blob SHA and SHA-256 in two manifests under `vendor/phase2/`. The original phase-one snapshot and its nine unconfirmed records remain unchanged.', '',
             '## Call graph legend', '',
             'Solid arrows show calls or data routes visible in pinned source. Dashed arrows cross generated-code boundaries inferred from the independently pinned AIDL generator. Diagram operation arrows summarize execution order; they do not claim the helper calls the operation. The service invokes the helper, then continues only if it returns.', '',
             '```mermaid', 'flowchart TD',
             '  SC[SerialManager] --> SI[ISerialManager methods]',
             '  SI -. generated Binder dispatch .-> SS[SerialService override]',
             '  SS --> SH[super.method_enforcePermission]',
             '  SH -. generated helper: Binder PID and UID .-> PE[PermissionEnforcer.enforcePermission]',
             '  PE --> DC[checkPermission and deny on failure]',
             '  SS --> LP[After helper: list available ports]',
             '  SS --> SO[After helper: supplier.get]',
             '  SO --> TO[Configured supplier only: tryOpen]',
             '  TO --> OS[Os.open]',
             '  SL[SerialService.Lifecycle] --> LS[LocalServices: same process]',
             '  LS --> LM[Add or remove virtual test port]',
             '```', '',
             '```mermaid', 'flowchart TD',
             '  IC[ConsumerIrManager] --> II[IConsumerIrService methods]',
             '  II -. generated Binder dispatch .-> IS[ConsumerIrService override]',
             '  IS --> IH[transmit or getCarrierFrequencies helper]',
             '  IH -. generated helper: Binder PID and UID .-> EP[PermissionEnforcer.enforcePermission]',
             '  IS --> IO[After helper returns: AIDL HAL or native fallback]',
             '  II -. generated Binder dispatch .-> IQ[hasIrEmitter]',
             '  IQ --> IB[Return capability boolean: RequiresNoPermission]',
             '```', '',
             'The generated helper is explicitly called by each protected service override. An AIDL annotation by itself is not treated as proof of enforcement. SerialService injects PermissionEnforcer explicitly; ConsumerIrService relies on its implicit superclass constructor, whose enforcer initialization is inferred from the generator reference.', '',
             '## Review records', '']
    for item in data['services'] + data['local_routes']:
        lines += [f"### {item['id']}", '', '| Field | Evidence / assessment |', '| --- | --- |',
                  f"| Service Name | `{item['service_name']}` |", f"| Entry Point | `{item['entry_point']}` |",
                  f"| Caller Identity | {item['caller_identity']} |", f"| Required Permission | {item['required_permission']} |",
                  f"| Enforcement Location | {markdown_ref(item['enforcement_location']) if item['enforcement_location'] else 'No helper: intentional no-permission query or same-process local API; see evidence'} |",
                  f"| Protected Operation | {', '.join(item['protected_operation']) if isinstance(item['protected_operation'], list) else item['protected_operation']} |",
                  f"| Source File and Line | {markdown_ref(item['source_file_and_line'])} |",
                  f"| AOSP Commit | `{item['aosp_commit']}` |",
                  f"| Confidence Level | {json.dumps(item['confidence_level'])} |",
                  f"| Validation Status | **{item['validation_status']}** |",
                  f"| Recommended Next Step | {item['recommended_next_step']} |", '', 'Source evidence:', '']
        for e in item['evidence']:
            lines.append(f"- {markdown_ref(e)} — `{e['excerpt'].replace('`', '')}`")
        if 'security_analysis' in item:
            checks = item['security_analysis']
            lines += ['', 'Security assessment:', '',
                      f"- Permission before operation: `{json.dumps(checks['permission_before_operation'])}`.",
                      f"- Caller UID/PID: {checks['caller_identity']}. These selected AIDL methods are not declared oneway; Binder.java also warns PID may be zero in certain transactions. Native Binder credential behavior was not tested.",
                      f"- Exceptions: catch types `{checks['exception_handling']['catch_types']}`. {checks['exception_handling']['conclusion']}.",
                      f"- Binder identity: {checks['identity_management']['conclusion']}; no local clear/restore calls found in this body. This does not audit all callees.",
                      f"- Alternate routes: {checks['alternate_routes']}",
                      f"- Permission suitability: {checks['permission_suitability']}.", '',
                      'Runtime validation cases (planned, not executed):', '', '| Case | Expected | Actual |', '| --- | --- |']
            for case in item['runtime_test_cases']:
                lines.append(f"| {case['case']} | {case['expected']} | **{case['actual']}** |")
        lines.append('')
    lines += ['## Supporting paths and identity evidence', '']
    for name, e in data['supporting_evidence'].items():
        lines.append(f"- **{name}**: {markdown_ref(e)} — `{e['excerpt']}`")
    lines += ['', 'Generator reference evidence (separate repository/revision):', '']
    for e in data['generator_evidence']:
        lines.append(f"- {markdown_ref(e)} — `{e['excerpt']}`")
    lines += ['', '## Security conclusions within the inspected slice', '',
              '- **SerialService:** both Binder methods call their generated permission helper as their first executable statement. The port open path looks up an allowed configured/virtual supplier, invokes it, and the configured supplier reaches `tryOpen` → `Os.open`. The caught `ErrnoException` surrounds the later OS open, not permission enforcement. No denial-swallowing catch appears around either helper.',
              '- **Serial local route:** Lifecycle publishes `SerialManagerInternal` through LocalServices. Add/remove virtual-port methods mutate the map under synchronization and enforce the `virtual:` name contract. LocalServices documents same-process objects, not Binder objects. This is an alternate trusted in-process mutation route, not demonstrated unprivileged Binder access. Full consumer enumeration remains out of scope.',
              '- **ConsumerIrService:** transmit and frequency query call their helpers first. AIDL HAL and native fallback calls both follow the helper. `RemoteException` catches surround later HAL calls, not the initial helper. `packageName` is not used as permission identity in this body; that is not itself a bypass because the expected helper uses Binder identity.',
              '- **Capability query:** `hasIrEmitter` is explicitly `@RequiresNoPermission` in AIDL and Java, and returns a boolean. Its lack of a helper is not labeled a missing-permission vulnerability.',
              '- **Permission strength:** the manifest declares SERIAL_PORT as `signature|privileged` and TRANSMIT_IR as `normal`. A normal permission can be granted to an app which requests it; that is intended permission policy, not evidence of a bypass. Suitability is source-consistent, not an independent proof of policy correctness.',
              '- No explicit clear/restore identity calls occur in the reviewed entry bodies. The inferred generated helper obtains Binder PID/UID. Same-process calls can observe process identity rather than an external caller; caller provenance beyond the selected slice is not proven.', '',
              '## Phase-one false-positive reduction', '',
              '| Original line | Classification | Assessment |', '| --- | --- | --- |']
    for m in data['phase_one_reclassification']:
        lines.append(f"| {m['line']} | {m['kind']} | Source token occurrence only; not a confirmed weakness |")
    lines += ['', 'Two of the original nine matches are declarations, seven are invocations. Their positions are preserved for audit. Neither a declaration nor a real permission-check call is sufficient vulnerability evidence.', '',
              '## Safe local validation: expected versus actual', '',
              '**Only hardcoded Python models were executed. No Android runtime, emulator, generated AIDL code, device, serial port or IR hardware was invoked.**', '',
              '| Model case | Expected | Actual | Pass |', '| --- | --- | --- | --- |']
    for check in data['validation']['checks']:
        lines.append(f"| {check['name']} | `{json.dumps(check['expected'])}` | `{json.dumps(check['actual'])}` | {check['passed']} |")
    lines += ['', 'The identity-clearing and swallowed-denial mutation cases deliberately show a bad model reaching a synthetic operation. They test whether the test harness detects faulty ordering; they are not behaviors observed in either AOSP service.', '',
              'Tool availability at analysis time: `' + json.dumps(data['environment_tools']) + '`.', '',
              '**Android runtime result: NOT RUN. Validation status for possible security weaknesses: Unconfirmed. Independently validated vulnerabilities: 0.**', '',
              '## Limitations', '']
    lines += ['- ' + value for value in data['limitations']]
    lines += ['', '## Recommended next steps', '',
              '1. Resolve a complete Android build manifest for the chosen frameworks revision and its exact AIDL compiler; generate and preserve ISerialManager/IConsumerIrService Stub output plus hashes.',
              '2. In a separately authorized emulator or isolated Android test runtime, inject a fake enforcer and fake operation sink. For each guarded entry run denied and permitted callers; denied cases must have zero sink invocations. Record the Binder UID/PID at enforcement.',
              '3. Use two test processes for actual Binder transactions; separate them from direct same-process Java calls. Verify no identity clearing occurs before enforcement and permission exceptions propagate. Keep real serial/IR devices disabled.',
              '4. Expand pinned source to enumerate LocalServices consumers and any JNI/HAL paths. Review service-manager/SELinux exposure and supported Android-version differences before making reachability claims.',
              '5. Only after a repeatable unauthorized protected operation has been demonstrated, assess root cause/impact, propose a minimal patch and verify a regression test. Otherwise retain Unconfirmed or reject a falsified hypothesis.', '',
              '## Reproduce', '', '```sh', 'python3 -m darkforge callgraph --source vendor/phase2 --destination evidence/phase2',
              'python3 scripts/phase2.py', 'sh scripts/test.sh', '```', '',
              'The first command regenerates the evidence and report in the destination. The second also copies the report to this repository-root filename. Both use the existing bounded worker limits. Raw graph edges with evidence types are in `evidence/phase2/callgraph.json`; a Mermaid graph is in `evidence/phase2/callgraph.mmd`.', '']
    return '\n'.join(lines)


def mermaid(data):
    nodes = {}
    lines = ['flowchart TD']
    def node(label):
        if label not in nodes:
            key = f'N{len(nodes)}'
            nodes[label] = key
            safe = label.replace('"', "'").replace('<', '&lt;').replace('>', '&gt;')
            lines.append(f'  {key}["{safe}"]')
        return nodes[label]
    for edge in data['graph_edges']:
        source, target = node(edge['source']), node(edge['target'])
        arrow = '-.->' if edge['kind'].startswith('inferred') else '-->'
        lines.append(f"  {source} {arrow}|{edge['kind']}| {target}")
    return '\n'.join(lines)+'\n'


def export(root, destination):
    result = analyze(root)
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'callgraph.json').write_text(json.dumps(result, indent=2)+'\n')
    (out / 'callgraph.mmd').write_text(mermaid(result))
    (out / 'AOSP_CALL_GRAPH_REVIEW.md').write_text(render_report(result))
    return dict(services=2, binder_entries=len(result['services']), local_routes=len(result['local_routes']),
                phase_one_declarations=sum(m['kind']=='declaration' for m in result['phase_one_reclassification']),
                phase_one_invocations=sum(m['kind']=='invocation' for m in result['phase_one_reclassification']),
                model_checks_passed=result['validation']['passed'], android_runtime_validation='NOT RUN',
                independently_validated_vulnerabilities=0, files=[str(out/p) for p in ['callgraph.json','callgraph.mmd','AOSP_CALL_GRAPH_REVIEW.md']])
