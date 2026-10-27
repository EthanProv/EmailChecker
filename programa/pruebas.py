import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from leer_correo import parse, MAX_MESSAGE, MAX_ATTACHMENT
from inteligencia import analyze, validate
from analizar import decidir as decide
from reputacion import Reputation
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

    def test_ai_uses_one_call_with_timeout(self):
        calls = []
        def fake(base, path, payload=None, timeout=None):
            calls.append((path, timeout))
            return {'message': {'content': json.dumps({'classification': 'sin_indicios_suficientes', 'reasons': ['SIMULATED'], 'evidence': []})}}
        with patch.dict(os.environ, {'AI_TIMEOUT': '25'}):
            self.assertEqual(analyze(self.sample('01_legitimate'), fake)['status'], 'ok')
        self.assertEqual(calls, [('/api/chat', 25)])

    def test_mock_invalid_reputation_never_clean(self):
        from io import BytesIO
        for provider, body in [('vt', {'data': {'attributes': {'last_analysis_stats': {}}}}), ('gsb', [])]:
            with tempfile.TemporaryDirectory(dir='results') as folder, patch('urllib.request.urlopen', side_effect=lambda *a, **k: BytesIO(json.dumps(body).encode())), patch('reputacion.time.sleep'):
                rep = Reputation(str(Path(folder) / 'cache.db'))
                self.assertEqual(rep.query(provider, 'https://test.example', {})['status'], 'unavailable')
                rep.db.close()

    def test_mock_invalid_model_response(self):
        def fake(base, path, *args, **kwargs):
            return {'message': {'content': 'NOT JSON'}}
        self.assertEqual(analyze(self.sample('01_legitimate'), fake)['status'], 'unavailable')

    def test_missing_model(self):
        from urllib.error import HTTPError
        with patch('inteligencia.urllib.request.urlopen', side_effect=HTTPError('http://localhost', 404, 'Modelo no encontrado', {}, None)):
            self.assertEqual(analyze(self.sample('01_legitimate'))['status'], 'unavailable')

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


import io
import struct
from servidor import Handler

def packet(command, data=b''):
    return struct.pack('!I', len(data) + 1) + command + data

class MilterTests(unittest.TestCase):
    def run_protocol(self, classification, audit_failure=False, reputation=None):
        handler = Handler.__new__(Handler)
        handler.rfile = io.BytesIO(packet(b'O', struct.pack('!III', 6, 0x20, 0)) + packet(b'M', b'<a@empresa.lab>\0') + packet(b'L', b'Subject\0Test\0') + packet(b'N') + packet(b'B', b'Hola') + packet(b'E') + packet(b'Q'))
        handler.wfile = io.BytesIO()
        ai = {'status': 'ok', 'classification': classification, 'reasons': ['SIMULATED TEST']}
        # Only this test mocks inference and audit file operations.
        with patch('analizar.analyze', return_value=ai), patch('servidor.Reputation') as rep, patch('servidor.Path') as path, patch('servidor.os.fsync'):
            rep.return_value.analyze.return_value = reputation or {'status': 'disabled_demo', 'items': []}
            path.return_value.__truediv__.return_value.name = 'SIMULATED.json'
            if audit_failure:
                path.return_value.__truediv__.return_value.open.side_effect = OSError('SIMULATED DISK FAILURE')
            handler.handle()
            rep.return_value.analyze.assert_called_once()
            rep.return_value.db.close.assert_called_once()
        output = io.BytesIO(handler.wfile.getvalue())
        commands = []
        while prefix := output.read(4):
            commands.append(output.read(struct.unpack('!I', prefix)[0])[:1])
        return commands

    def test_hold_action(self):
        self.assertEqual(self.run_protocol('sospechoso')[-2:], [b'q', b'c'])

    def test_allow_without_reinjection(self):
        self.assertNotIn(b'q', self.run_protocol('sin_indicios_suficientes'))

    def test_virustotal_detection_holds_even_if_ai_allows(self):
        rep = {'status': 'ok', 'items': [{'provider': 'vt', 'status': 'malicious'}]}
        self.assertEqual(self.run_protocol('sin_indicios_suficientes', reputation=rep)[-2:], [b'q', b'c'])

    def test_unknown_virustotal_report_needs_review(self):
        rep = {'status': 'unknown', 'items': [{'provider': 'vt', 'status': 'unknown'}]}
        self.assertEqual(self.run_protocol('sin_indicios_suficientes', reputation=rep)[-2:], [b'q', b'c'])

    def test_virustotal_failure_never_allows(self):
        rep = {'status': 'unavailable', 'items': [{'provider': 'vt', 'status': 'unavailable'}]}
        self.assertEqual(self.run_protocol('sin_indicios_suficientes', reputation=rep)[-2:], [b'q', b'c'])

import contextlib

from analizar import main, revisar_correo
from analizar import crear_informe as render


class CliTests(unittest.TestCase):
    def test_report_escapes_mail_and_shows_ai_failure(self):
        report = render([{'id': '<img src=x onerror=alert(1)>', 'decision': 'pendiente de revisión',
                          'seconds': 1, 'reasons': ['<script>alert(1)</script>'],
                          'ai': {'status': 'unavailable'}}])
        self.assertNotIn('<script>', report)
        self.assertNotIn('<img ', report)
        self.assertIn('&lt;script&gt;', report)
        self.assertIn('pendiente de revisión', report)

    def test_empty_batch_is_clear_error(self):
        with tempfile.TemporaryDirectory(dir='results') as folder:
            with patch('sys.argv', ['emailchecker', folder]), contextlib.redirect_stderr(io.StringIO()) as error:
                with self.assertRaises(SystemExit) as exc:
                    main()
                self.assertEqual(exc.exception.code, 2)
                self.assertIn('carpeta esta vacia', error.getvalue())

    def test_unavailable_ai_needs_review(self):
        with patch('analizar.analyze', return_value={'status': 'unavailable', 'classification': 'indeterminado'}):
            reputation = unittest.mock.Mock()
            reputation.analyze.return_value = {'status': 'disabled_demo', 'items': []}
            result = revisar_correo(Path('samples/01_legitimate.eml').read_bytes(), reputation)
            self.assertEqual(result['ai']['status'], 'unavailable')
            self.assertEqual(result['decision'], 'pendiente de revisión')

    def test_audit_failure_blocks_delivery(self):
        self.assertEqual(MilterTests().run_protocol('sin_indicios_suficientes', audit_failure=True)[-1], b't')

    def test_known_mismatch_quarantined_without_calling_ai(self):
        with patch('analizar.analyze', side_effect=AssertionError('No AI needed')):
            reputation = unittest.mock.Mock()
            reputation.analyze.return_value = {'status': 'disabled_demo', 'items': []}
            result = revisar_correo(Path('samples/04_mismatch.eml').read_bytes(), reputation)
            self.assertEqual(result['decision'], 'cuarentena')
            self.assertEqual(result['ai']['status'], 'skipped_static')


class VirusTotalTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir='results')
        self.env = patch.dict(os.environ, {'REPUTATION_HASHES': '1', 'REPUTATION_URLS': '0', 'VT_API_KEY': 'SIMULATED_KEY_NOT_REAL', 'GSB_API_KEY': ''})
        self.env.start()
        self.rep = Reputation(str(Path(self.folder.name) / 'cache.sqlite'))
        self.correo = parse(Path('samples/02_attachment.eml').read_bytes())

    def tearDown(self):
        self.rep.db.close()
        self.env.stop()
        self.folder.cleanup()

    def respuesta(self, malicious=0):
        from io import BytesIO
        return BytesIO(json.dumps({'data': {'attributes': {'last_analysis_stats': {'malicious': malicious, 'suspicious': 0, 'harmless': 20}}}}).encode())

    def test_hash_lookup_only_get_and_cache_across_messages(self):
        with patch('urllib.request.urlopen', side_effect=lambda *a, **k: self.respuesta()) as network:
            first = self.rep.analyze(self.correo)
            second = Reputation(str(Path(self.folder.name) / 'cache.sqlite'))
            try:
                cached = second.analyze(self.correo)
            finally:
                second.db.close()
        request = network.call_args.args[0]
        self.assertEqual(request.get_method(), 'GET')
        self.assertIsNone(request.data)
        self.assertTrue(request.full_url.endswith('/files/' + self.correo['attachments'][0]['sha256']))
        self.assertEqual(network.call_count, 1)
        self.assertLessEqual(network.call_args.kwargs['timeout'], 8)
        self.assertEqual(first['items'][0]['status'], 'no_known_detection')
        self.assertTrue(cached['items'][0]['cached'])
        self.assertNotIn('SIMULATED_KEY_NOT_REAL', json.dumps(first))

    def test_real_policy_uses_virustotal_detection(self):
        with patch('urllib.request.urlopen', side_effect=lambda *a, **k: self.respuesta(2)), patch('analizar.analyze', return_value={'status': 'ok', 'classification': 'sin_indicios_suficientes'}):
            result = revisar_correo(Path('samples/02_attachment.eml').read_bytes(), self.rep)
        self.assertEqual(result['decision'], 'cuarentena')
        self.assertEqual(result['reputation']['items'][0]['status'], 'malicious')

    def test_unknown_hash_is_not_clean(self):
        from urllib.error import HTTPError
        with patch('urllib.request.urlopen', side_effect=HTTPError('https://www.virustotal.com', 404, 'Unknown', {}, None)):
            result = self.rep.analyze(self.correo)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(decide(self.correo, {'status': 'ok', 'classification': 'sin_indicios_suficientes'}, result)[0], 'pendiente de revisión')

    def test_429_is_unavailable_and_cools_down(self):
        import time
        from urllib.error import HTTPError
        with patch('urllib.request.urlopen', side_effect=HTTPError('https://www.virustotal.com', 429, 'Quota', {}, None)):
            result = self.rep.analyze(self.correo)
        self.assertEqual(result['status'], 'unavailable')
        self.assertGreater(self.rep.db.execute("SELECT next FROM quota WHERE provider='vt'").fetchone()[0], time.time() + 50)

    def test_timeout_is_unavailable_without_retry(self):
        with patch('urllib.request.urlopen', side_effect=TimeoutError('SIMULATED')) as network:
            result = self.rep.analyze(self.correo)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(network.call_count, 1)

    def test_budget_exhaustion_never_queries(self):
        with patch('reputacion.time.monotonic', side_effect=[0, 9]), patch('urllib.request.urlopen') as network:
            result = self.rep.analyze(self.correo)
        self.assertEqual(result['items'][0]['error'], 'time_budget')
        network.assert_not_called()

    def test_multiple_new_hashes_respect_quota(self):
        self.correo['attachments'].append({'sha256': 'f' * 64})
        with patch('urllib.request.urlopen', side_effect=lambda *a, **k: self.respuesta()) as network:
            result = self.rep.analyze(self.correo)
        self.assertEqual(network.call_count, 1)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(result['items'][1]['error'], 'local_quota')

    def test_urls_use_virustotal_without_requiring_google_key(self):
        with patch.dict(os.environ, {'REPUTATION_HASHES': '0', 'REPUTATION_URLS': '1'}), patch('urllib.request.urlopen', side_effect=lambda *a, **k: self.respuesta()) as network:
            result = self.rep.analyze(self.correo)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(network.call_count, 1)
        self.assertIn('virustotal.com/api/v3/urls/', network.call_args.args[0].full_url)


if __name__ == '__main__':
    unittest.main()
