"""Opt-in read-only reputation; never uploads bytes or submits scans."""
import base64
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

class Reputation:
    def __init__(self, cache='results/cache.sqlite'):
        Path(cache).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(cache)
        self.db.execute('CREATE TABLE IF NOT EXISTS quota (provider TEXT PRIMARY KEY, next REAL)')

    def query(self, provider, url, headers):
        # Un limite persistente evita acumular peticiones entre ejecuciones.
        self.db.execute('BEGIN IMMEDIATE')
        row = self.db.execute('SELECT next FROM quota WHERE provider=?', (provider,)).fetchone()
        if row and row[0] > time.time():
            self.db.commit()
            return {'status': 'unavailable', 'error': 'local_quota'}
        self.db.execute('INSERT OR REPLACE INTO quota VALUES (?,?)', (provider, time.time() + (16 if provider == 'vt' else 1)))
        self.db.commit()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=10) as response:
                raw = response.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise ValueError('response_limit')
                data = json.loads(raw)
            if provider == 'vt':
                stats = data['data']['attributes']['last_analysis_stats']
                if not isinstance(stats, dict) or not {'malicious', 'suspicious'} <= stats.keys():
                    raise ValueError('invalid_vt_stats')
                if any(type(n) is not int or n < 0 for n in stats.values()):
                    raise ValueError('invalid_vt_stats')
                detected = stats['malicious'] or stats['suspicious']
            else:
                if not isinstance(data, dict) or not isinstance(data.get('threats', []), list):
                    raise ValueError('invalid_gsb_response')
                detected = bool(data.get('threats'))
            return {'status': 'malicious' if detected else 'no_known_detection', 'provider': provider, 'attribution': 'Google Safe Browsing' if provider == 'gsb' else 'VirusTotal'}
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                self.db.execute('INSERT OR REPLACE INTO quota VALUES (?,?)', (provider, time.time() + 60))
                self.db.commit()
            return {'status': 'unknown' if provider == 'vt' and exc.code == 404 else 'unavailable', 'error': 'http_' + str(exc.code)}
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return {'status': 'unavailable', 'error': 'network_or_invalid_response'}

    def analyze(self, parsed):
        hashes, urls = os.getenv('REPUTATION_HASHES') == '1', os.getenv('REPUTATION_URLS') == '1'
        if not hashes and not urls:
            return {'status': 'disabled_demo', 'items': [], 'note': 'Sin consultas; no son resultados limpios ni simulados.'}
        items = []
        vt, gsb = os.getenv('VT_API_KEY'), os.getenv('GSB_API_KEY')
        targets = [('hash', a['sha256']) for a in parsed['attachments'] if hashes and a['sha256']]
        targets += [('url', u) for u in sorted({u['href'] for u in parsed['urls']}) if urls]
        for kind, target in targets:
            providers = ['vt'] if kind == 'hash' else ['vt', 'gsb']
            for provider in providers:
                if not (vt if provider == 'vt' else gsb):
                    value = {'status': 'unavailable', 'error': 'missing_key'}
                elif provider == 'vt':
                    identifier = target if kind == 'hash' else base64.urlsafe_b64encode(target.encode()).decode().rstrip('=')
                    value = self.query('vt', 'https://www.virustotal.com/api/v3/' + ('files/' if kind == 'hash' else 'urls/') + identifier, {'x-apikey': vt})
                else:
                    value = self.query('gsb', 'https://safebrowsing.googleapis.com/v5/urls:search?' + urllib.parse.urlencode({'urls': target}), {'X-Goog-Api-Key': gsb})
                items.append({'provider': provider, 'kind': kind, 'target': target, **value})
        return {'status': 'unavailable' if any(x['status'] == 'unavailable' for x in items) else 'ok', 'items': items}
