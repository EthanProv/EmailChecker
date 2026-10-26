import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from antiphishing.parser import parse, MAX_MESSAGE, MAX_ATTACHMENT
from antiphishing.ai import analyze, validate
from antiphishing.policy import decide
from antiphishing.reputation import Reputation
from email.message import EmailMessage

class AnalyzerTests(unittest.TestCase):
    def sample(self, name):
        return parse(Path('samples', name + '.eml').read_bytes())

    def test_mismatch(self):
        self.assertTrue(self.sample('04_mismatch')['urls'][0]['mismatch'])

    def test_generic_link_not_mismatch(self):
        self.assertFalse(any(x['mismatch'] for x in self.sample('02_attachment')['urls']))

    def test_decoded_hash(self):
        self.assertEqual(self.sample('02_attachment')['attachments'][0]['sha256'], hashlib.sha256(b'Acta de laboratorio. Archivo inocuo.\n').hexdigest())

    def test_alternatives_not_duplicated(self):
        self.assertEqual(self.sample('06_mime')['text'].count('Información de la sesión'), 1)
        self.assertNotIn('alternative_html_text', self.sample('06_mime'))

    def test_different_html_content_preserved(self):
        msg = EmailMessage()
        msg.set_content('Hola')
        msg.add_alternative('<p>Introduce tu contraseña</p>', subtype='html')
        self.assertIn('contraseña', parse(msg.as_bytes())['alternative_html_text'])

    def test_valid_and_invalid_schema(self):
        valid = {'classification': 'sospechoso', 'reasons': ['petición'], 'evidence': ['contraseña']}
        self.assertEqual(validate(valid, 'tu contraseña'), valid)
        for wrong in [{}, {**valid, 'classification': 'seguro'}, {**valid, 'evidence': ['inventada']}, {**valid, 'reasons': 'texto'}]:
            with self.assertRaises(ValueError):
                validate(wrong, 'tu contraseña')

    def test_mock_timeout_never_allow(self):
        def timeout(*args, **kwargs):
            raise TimeoutError('SIMULATED TEST')
        static = self.sample('01_legitimate')
        ai = analyze(static, timeout)
        self.assertEqual(ai['status'], 'unavailable')
        self.assertEqual(decide(static, ai, {'status': 'disabled_demo', 'items': []})[0], 'pendiente de revisión')

    def test_evidence_decodes_json_escapes(self):
        text = 'Perfecto\r\n"Prueba" \\ carpeta\r\n'
        value = {'classification': 'sin_indicios_suficientes', 'reasons': ['Sin señales'], 'evidence': [text]}
        self.assertEqual(validate(value, json.dumps({'text': text})), value)
        with self.assertRaises(ValueError):
            validate({**value, 'evidence': ['texto inventado']}, json.dumps({'text': text}))

    def test_mock_ai_total_budget_includes_metadata(self):
        budgets = []
        def fake(base, path, payload=None, timeout=None):
            budgets.append(timeout)
            if path == '/api/tags':
                return {'models': [{'name': 'qwen3:4b', 'digest': 'SIMULATED'}]}
            if path == '/api/version':
                return {'version': 'SIMULATED'}
            return {'message': {'content': json.dumps({'classification': 'sin_indicios_suficientes', 'reasons': ['SIMULATED'], 'evidence': []})}}
        with patch.dict(os.environ, {'AI_TIMEOUT': '25'}), patch('antiphishing.ai.time.monotonic', side_effect=[0, 1, 8, 20]):
            self.assertEqual(analyze(self.sample('01_legitimate'), fake)['status'], 'ok')
        self.assertEqual(budgets, [10, 10, 5])

    def test_mock_invalid_reputation_never_clean(self):
        from io import BytesIO
        for provider, body in [('vt', {'data': {'attributes': {'last_analysis_stats': {}}}}), ('gsb', [])]:
            with tempfile.TemporaryDirectory(dir='results') as folder, patch('urllib.request.urlopen', side_effect=lambda *a, **k: BytesIO(json.dumps(body).encode())), patch('antiphishing.reputation.time.sleep'):
                rep = Reputation(str(Path(folder) / 'cache.db'))
                self.assertEqual(rep.query(provider, 'SIMULATED', 'https://test.example', {})['status'], 'unavailable')
                rep.db.close()

    def test_mock_invalid_model_response(self):
        def fake(base, path, *args, **kwargs):
            if path == '/api/tags':
                return {'models': [{'name': 'qwen3:4b', 'digest': 'SIMULATED'}]}
            if path == '/api/version':
                return {'version': 'SIMULATED'}
            return {'message': {'content': 'NOT JSON'}}
        self.assertEqual(analyze(self.sample('01_legitimate'), fake)['status'], 'unavailable')

    def test_missing_model(self):
        self.assertEqual(analyze(self.sample('01_legitimate'), lambda *a, **k: {'models': []})['status'], 'unavailable')

    def test_limits(self):
        self.assertIn('message_size_limit', parse(b'a' * (MAX_MESSAGE + 1))['incomplete'])
        msg = EmailMessage()
        msg.set_content('Hola')
        msg.add_attachment(b'a' * (MAX_ATTACHMENT + 1), maintype='application', subtype='octet-stream', filename='large.txt')
        parsed = parse(msg.as_bytes())
        self.assertIn('attachment_size_limit', parsed['incomplete'])
        self.assertIsNone(parsed['attachments'][0]['sha256'])

    def test_reputation_disabled_no_network(self):
        with tempfile.TemporaryDirectory(dir='results') as folder, patch.dict(os.environ, {'REPUTATION_HASHES': '0', 'REPUTATION_URLS': '0'}), patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            rep = Reputation(str(Path(folder) / 'cache.db'))
            self.assertEqual(rep.analyze(self.sample('02_attachment'))['status'], 'disabled_demo')
            rep.db.close()

    def test_reputation_missing_key(self):
        with tempfile.TemporaryDirectory(dir='results') as folder, patch.dict(os.environ, {'REPUTATION_HASHES': '1', 'VT_API_KEY': '', 'REPUTATION_URLS': '0'}):
            rep = Reputation(str(Path(folder) / 'cache.db'))
            self.assertEqual(rep.analyze(self.sample('02_attachment'))['status'], 'unavailable')
            rep.db.close()

    def test_cloud_rejected(self):
        with patch.dict(os.environ, {'OLLAMA_URL': 'https://ollama.com'}):
            self.assertEqual(analyze(self.sample('01_legitimate'))['error'], 'nonlocal_endpoint_or_model_rejected')

if __name__ == '__main__':
    unittest.main()

