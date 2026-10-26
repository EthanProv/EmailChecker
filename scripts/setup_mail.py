"""Create private lab credentials and TLS certificate; do not overwrite."""
import json
import secrets
import shutil
import subprocess
from pathlib import Path

folder = Path('mail-config')
folder.mkdir(exist_ok=True)
patch_file = folder / 'user-patches.sh'
if not patch_file.exists():
    shutil.copyfile(Path(__file__).with_name('enable-milter.sh'), patch_file)
compose = ['docker', 'compose', '-f', 'compose.yaml', '-f', 'compose.gpu.yaml', '-f', 'compose.mail.yaml']
if not (folder / 'cert.pem').exists():
    subprocess.run(compose + ['run', '--rm', '--no-deps', '--entrypoint', 'openssl', 'mailserver', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '365', '-keyout', '/tmp/docker-mailserver/key.pem', '-out', '/tmp/docker-mailserver/cert.pem', '-subj', '/CN=localhost', '-addext', 'basicConstraints=critical,CA:false', '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment', '-addext', 'extendedKeyUsage=serverAuth', '-addext', 'subjectAltName=DNS:localhost,DNS:mail.empresa.lab,IP:127.0.0.1,IP:::1'], check=True)
credentials_path = folder / 'credentials.json'
if not credentials_path.exists():
    credentials_path.write_text(json.dumps({u + '@empresa.lab': secrets.token_urlsafe(24) for u in ('alumno', 'docente')}, indent=2), encoding='utf-8')
accounts = credentials_path.read_text(encoding='utf-8')
if not (folder / 'postfix-accounts.cf').exists():
    for address, password in json.loads(accounts).items():
        subprocess.run(compose + ['run', '--rm', '--no-deps', 'mailserver', 'setup', 'email', 'add', address, password], check=True, stdout=subprocess.DEVNULL)
print('TLS y dos cuentas de laboratorio preparados; credenciales en mail-config/credentials.json (excluido de Git).')
