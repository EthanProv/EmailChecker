"""Repair only the two local lab accounts in the existing Thunderbird profile."""
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
from datetime import datetime
from pathlib import Path

if subprocess.run(['tasklist', '/FI', 'IMAGENAME eq thunderbird.exe'], capture_output=True, text=True).stdout.lower().find('thunderbird.exe') >= 0:
    raise SystemExit('Close Thunderbird before running this repair.')
profile = Path(os.environ['APPDATA']) / 'Thunderbird/Profiles/ucz2gg7u.default-release'
backup = profile / ('lab-backup-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
backup.mkdir()
for name in ('prefs.js', 'cert_override.txt', 'user.js'):
    if (profile / name).exists():
        shutil.copy2(profile / name, backup / name)
prefs = (profile / 'prefs.js').read_text(encoding='utf-8')
updates = {}
for server, identity, smtp, user in [('server1', 'id1', 'smtp1', 'docente'), ('server4', 'id2', 'smtp2', 'alumno')]:
    address = user + '@empresa.lab'
    for key, value in {'hostname': '127.0.0.1', 'port': 1993, 'socketType': 3, 'authMethod': 3, 'userName': address}.items():
        updates[f'mail.server.{server}.{key}'] = value
    for key, value in {'hostname': '127.0.0.1', 'port': 465, 'try_ssl': 3, 'authMethod': 3, 'username': address, 'description': user.capitalize() + ' laboratorio (TLS)'}.items():
        updates[f'mail.smtpserver.{smtp}.{key}'] = value
    updates[f'mail.identity.{identity}.smtpServer'] = smtp
    updates[f'mail.identity.{identity}.reply_to'] = ''
updates['mail.smtp.defaultserver'] = 'smtp1'
for key, value in updates.items():
    line = f'user_pref({json.dumps(key)}, {json.dumps(value)});'
    pattern = r'^user_pref\(' + re.escape(json.dumps(key)) + r', .*?\);$'
    if re.search(pattern, prefs, re.M):
        prefs = re.sub(pattern, lambda _: line, prefs, flags=re.M)
    else:
        prefs += '\n' + line
(profile / 'prefs.js').write_text(prefs, encoding='utf-8')
override_path = profile / 'cert_override.txt'
old = override_path.read_text(encoding='utf-8') if override_path.exists() else '# PSM Certificate Override Settings file\n# This is a generated file!  Do not edit.\n'
lines = [line for line in old.splitlines() if not re.match(r'^(127\.0\.0\.1|localhost):(465|1587|1993|1143):?\s', line)]
cert = Path(__file__).resolve().parents[1] / 'mail-config/cert.pem'
digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
fingerprint = ':'.join(digest[i:i+2] for i in range(0, len(digest), 2))
for port in (465, 1993):
    lines.append(f'127.0.0.1:{port}:\tOID.2.16.840.1.101.3.4.2.1\t{fingerprint}\t')
override_path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('Repaired both lab accounts; certificate pinned for 127.0.0.1:465 and :1993.')
print('Backup:', backup)
