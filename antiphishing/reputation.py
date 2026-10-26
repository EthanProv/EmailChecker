"""Opt-in read-only reputation; never uploads bytes or submits scans."""
import base64
import hashlib
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
        self.db.execute('CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, expires REAL, value TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS quota (provider TEXT PRIMARY KEY, next REAL)')

    def query(self, provider, identifier, url, headers):
        key = hashlib.sha256((provider + identifier).encode()).hexdigest()
        cached = self.db.execute('SELECT expires,value FROM cache WHERE key=?', (key,)).fetchone()
        if cached and cached[0] > time.time():
            return {**json.loads(cached[1]), 'cached': True}
        # Persisted quota reservation also coordinates separate CLI processes.
        self.db.execute('BEGIN IMMEDIATE')
        row = self.db.execute('SELECT next FROM quota WHERE provider=?', (provider,)).fetchone()
        if row and row[0] > time.time():
            self.db.commit()
            return {'status': 'unavailable', 'error': 'local_quota'}
        self.db.execute('INSERT OR REPLACE INTO quota VALUES (?,?)', (provider, time.time() + (16 if provider == 'vt' else 1)))
        self.db.commit()
        value, ttl = {'status': 'unavailable'}, 0
        for attempt in range(2):
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=10) as response:
                    raw = response.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024:
                        raise ValueError('response_limit')
                    data = json.loads(raw)
                if provider == 'vt':
                    stats = data['data']['attributes']['last_analysis_stats']
                    if not isinstance(stats, dict) or not stats or any(type(n) is not int or n < 0 for n in stats.values()):
                        raise ValueError('invalid_vt_stats')
                    if 'malicious' not in stats or 'suspicious' not in stats:
                        raise ValueError('missing_vt_stats')
                    value = {'status': 'malicious' if stats.get('malicious', 0) or stats.get('suspicious', 0) else 'no_known_detection', 'stats': stats}
                    ttl = 3600
                else:
                    if not isinstance(data, dict) or not isinstance(data.get('threats', []), list):
                        raise ValueError('invalid_gsb_response')
                    value = {'status': 'malicious' if data.get('threats') else 'no_known_detection', 'attribution': 'Google Safe Browsing: posible amenaza, puede haber falsos positivos y negativos'}
                    ttl = min(3600, max(0, float(data.get('cacheDuration', '0s').rstrip('s'))))
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404 and provider == 'vt':
                    value, ttl = {'status': 'unknown'}, 300
                else:
                    value = {'status': 'unavailable', 'error': 'http_' + str(exc.code)}
                if exc.code == 429:
                    self.db.execute('INSERT OR REPLACE INTO quota VALUES (?,?)', (provider, time.time() + 60))
                    self.db.commit()
                # Do not consume quota retrying HTTP failures.
                break
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                value = {'status': 'unavailable', 'error': 'network_or_invalid_response'}
                if attempt == 0:
                    time.sleep(16 if provider == 'vt' else 1)
        if ttl:
            self.db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?)', (key, time.time() + ttl, json.dumps(value)))
            self.db.commit()
        return value

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
                    value = self.query('vt', target, 'https://www.virustotal.com/api/v3/' + ('files/' if kind == 'hash' else 'urls/') + identifier, {'x-apikey': vt})
                else:
                    value = self.query('gsb', target, 'https://safebrowsing.googleapis.com/v5/urls:search?' + urllib.parse.urlencode({'urls': target}), {'X-Goog-Api-Key': gsb})
                items.append({'provider': provider, 'kind': kind, 'target': target, **value})
        return {'status': 'unavailable' if any(x['status'] == 'unavailable' for x in items) else 'ok', 'items': items}
