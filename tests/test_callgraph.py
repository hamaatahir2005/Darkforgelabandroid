"""Source evidence, false-positive reduction, negative/positive local controls."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from darkforge.callgraph import (FRAMEWORK_COMMIT, GENERATOR_COMMIT, Corpus, ENFORCER,
                                SERIAL, IR, analyze, classify_permission_matches, export,
                                mask_java, method, methods, order_check, safe_model_validation)
from darkforge.source import PROJECT
from darkforge.limits import job

ROOT = PROJECT / 'vendor/phase2'


class CallGraphTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = analyze(ROOT)

    def test_pinned_sources_include_service_aidl_and_generator(self):
        data = self.data
        self.assertEqual(data['manifests']['frameworks']['commit'], FRAMEWORK_COMMIT)
        self.assertEqual(data['manifests']['aidl']['commit'], GENERATOR_COMMIT)
        self.assertEqual(len(data['manifests']['frameworks']['files']), 13)
        self.assertEqual(len(data['manifests']['aidl']['files']), 1)

    def test_all_requested_record_fields(self):
        required = {'service_name','entry_point','caller_identity','required_permission',
                    'enforcement_location','protected_operation','source_file_and_line',
                    'aosp_commit','confidence_level','validation_status','recommended_next_step'}
        self.assertEqual(len(self.data['services']), 5)
        self.assertEqual(len(self.data['local_routes']), 2)
        for record in self.data['services'] + self.data['local_routes']:
            self.assertTrue(required <= record.keys())
            self.assertIn('Unconfirmed', record['validation_status'])
            self.assertEqual(record['aosp_commit'], FRAMEWORK_COMMIT)
            self.assertTrue(record['evidence'])

    def test_four_guards_are_first_statement_before_all_selected_sinks(self):
        guarded = [r for r in self.data['services'] if r['enforcement_location']]
        self.assertEqual(len(guarded), 4)
        for record in guarded:
            check = record['security_analysis']['permission_before_operation']
            self.assertEqual(check['helper_invocations'], 1)
            self.assertTrue(check['helper_is_first_statement'])
            self.assertTrue(check['helper_before_all_protected_calls'])
            self.assertGreater(check['protected_calls'], 0)

    def test_intentional_no_permission_query_is_not_missing_guard(self):
        record = next(r for r in self.data['services'] if r['entry_point'].endswith('hasIrEmitter'))
        self.assertIsNone(record['enforcement_location'])
        self.assertIn('RequiresNoPermission', record['required_permission'])
        self.assertTrue(any('@RequiresNoPermission' in e['excerpt'] for e in record['evidence']))
        self.assertEqual(record['protected_operation'], ['return mHasNativeHal;'])

    def test_nine_hits_reclassified_with_exact_original_lines(self):
        matches = self.data['phase_one_reclassification']
        self.assertEqual([m['line'] for m in matches], [96,103,104,131,144,153,169,180,197])
        self.assertEqual(sum(m['kind']=='declaration' for m in matches), 2)
        self.assertEqual(sum(m['kind']=='invocation' for m in matches), 7)

    def test_comment_and_string_occurrences_do_not_become_calls(self):
        code = '''class Lab {
          // checkPermission("fake");
          String text = "checkPermission(fake) {";
          /* checkPermission(ignored) */
          protected int checkPermission(String p) { return 0; }
          public void entry() { checkPermission("real"); }
        }'''
        matches = classify_permission_matches(code)
        self.assertEqual([m['kind'] for m in matches], ['declaration', 'invocation'])
        self.assertEqual(mask_java(code).count('\n'), code.count('\n'))

    def test_overloaded_method_disambiguation(self):
        text = (ROOT/'frameworks'/SERIAL).read_text()
        spans = [m for m in methods(text) if m['name']=='getSerialPorts']
        self.assertEqual([m['line'] for m in spans], [67,88])
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            method(text, 'getSerialPorts')
        self.assertEqual(method(text, 'getSerialPorts', params='Context')['line'], 67)

    def test_negative_mutation_guard_after_sink_is_not_accepted(self):
        text = 'public void action() { sink.write(); super.action_enforcePermission(); }'
        check = order_check(text, method(text,'action'),'action_enforcePermission',['write'])
        self.assertFalse(check['helper_is_first_statement'])
        self.assertFalse(check['helper_before_all_protected_calls'])

    def test_positive_control_guard_before_sink(self):
        text = 'public void action() { super.action_enforcePermission(); sink.write(); }'
        check = order_check(text, method(text,'action'),'action_enforcePermission',['write'])
        self.assertTrue(check['helper_is_first_statement'])
        self.assertTrue(check['helper_before_all_protected_calls'])

    def test_conditional_guard_does_not_pass_first_statement_invariant(self):
        text = 'public void action() { if (flag) { super.action_enforcePermission(); } sink.write(); }'
        check = order_check(text, method(text,'action'),'action_enforcePermission',['write'])
        self.assertFalse(check['helper_is_first_statement'])
        self.assertIn('not a whole-program',check['limitation'])

    def test_no_local_identity_clear_or_denial_catch_in_selected_entries(self):
        for record in self.data['services']:
            analysis = record['security_analysis']
            self.assertEqual(analysis['identity_management']['observed_clear_or_restore_calls'], [])
            self.assertNotIn('SecurityException', analysis['exception_handling']['catch_types'])
        for name in ['transmit','getCarrierFrequencies']:
            record = next(r for r in self.data['services'] if r['entry_point'].endswith('.'+name))
            self.assertEqual(record['security_analysis']['exception_handling']['catch_types'], ['RemoteException'])
            self.assertTrue(record['security_analysis']['permission_before_operation']['helper_is_first_statement'])

    def test_every_citation_resolves_to_exact_pinned_line(self):
        count = 0
        def visit(value):
            nonlocal count
            if isinstance(value, dict):
                if {'repository','commit','path','line','excerpt','url'} <= value.keys():
                    group = 'aidl' if value['repository'].endswith('platform_system_tools_aidl') else 'frameworks'
                    manifest = self.data['manifests'][group]
                    self.assertEqual(value['commit'],manifest['commit'])
                    actual = (ROOT/group/value['path']).read_text().splitlines()[value['line']-1].strip()
                    self.assertEqual(value['excerpt'], actual)
                    self.assertTrue(value['url'].endswith('#L'+str(value['line'])))
                    count += 1
                for v in value.values(): visit(v)
            elif isinstance(value,list):
                for v in value: visit(v)
        visit(self.data)
        self.assertGreater(count,100)

    def test_generated_edges_are_inferred_and_runtime_cases_not_executed(self):
        inferred = [e for e in self.data['graph_edges'] if e['kind'].startswith('inferred')]
        self.assertEqual(len(inferred),9)  # five dispatch + four permission helper
        self.assertIn('NOT proven',self.data['generator_reference_limitation'])
        for edge in inferred:
            self.assertTrue(edge['evidence'])
        for record in self.data['services']:
            for case in record['runtime_test_cases']:
                self.assertEqual(case['actual'],'NOT RUN')
                self.assertEqual(case['status'],'unconfirmed')

    def test_local_routes_have_same_process_evidence(self):
        for record in self.data['local_routes']:
            self.assertIn('Same-process',record['caller_identity'])
            self.assertTrue(any('not Binder objects' in e['excerpt'] for e in record['evidence']))
            self.assertIsNone(record['enforcement_location'])

    def test_safe_models_report_expected_actual_and_mutation_controls(self):
        result=safe_model_validation()
        self.assertTrue(result['passed'])
        self.assertFalse(result['android_runtime_executed'])
        self.assertFalse(result['vulnerability_verified'])
        self.assertEqual(len(result['checks']),5)
        for check in result['checks']:
            self.assertEqual(check['expected'],check['actual'])
        controls=[c for c in result['checks'] if c['name'].startswith('mutation control')]
        self.assertEqual(len(controls),2)
        self.assertTrue(all(c['actual']['protected_operation_count']==1 for c in controls))

    def test_source_tampering_fails_before_graph_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'source'
            shutil.copytree(ROOT,copy)
            with (copy/'frameworks'/SERIAL).open('a') as file: file.write('\n// altered\n')
            with self.assertRaisesRegex(ValueError,'integrity'):
                analyze(copy)

    def test_valid_but_unexpected_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            copy=Path(d)/'source'
            shutil.copytree(ROOT,copy)
            path=copy/'frameworks/manifest.json'
            data=json.loads(path.read_text());data['commit']='f'*40;path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'baseline mismatch'):
                Corpus(copy)

    def test_bounded_export_generates_evidence_and_requested_report(self):
        with tempfile.TemporaryDirectory() as d:
            result=job('callgraph',dict(root=str(ROOT),destination=d),wall=15)
            self.assertEqual(result['independently_validated_vulnerabilities'],0)
            report=(Path(d)/'AOSP_CALL_GRAPH_REVIEW.md').read_text()
            self.assertIn('```mermaid',report)
            self.assertIn('Actual |',report)
            self.assertIn('NOT RUN',report)
            self.assertIn(FRAMEWORK_COMMIT,report)
            self.assertIn(GENERATOR_COMMIT,report)
            graph=(Path(d)/'callgraph.mmd').read_text()
            self.assertIn('-.->',graph)
            self.assertEqual(json.loads((Path(d)/'callgraph.json').read_text())['independently_validated_vulnerabilities'],0)
