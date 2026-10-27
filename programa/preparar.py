"""Prepara los archivos privados. Docker y las cuentas se arrancan desde lab.ps1."""
import json
import secrets
import shutil
from pathlib import Path

folder = Path('mail-config')
folder.mkdir(exist_ok=True)

# Este archivo conecta el servidor de correo con nuestro filtro.
patch_file = folder / 'user-patches.sh'
if not patch_file.exists():
    source = Path(__file__).with_name('activar_filtro.sh')
    shutil.copyfile(source, patch_file)

# Las contrasenas se crean una sola vez, para conservar las cuentas existentes.
credentials_file = folder / 'credentials.json'
if not credentials_file.exists():
    accounts = {}
    for name in ('alumno', 'docente'):
        accounts[name + '@empresa.lab'] = secrets.token_urlsafe(24)
    credentials_file.write_text(json.dumps(accounts, indent=2), encoding='utf-8')

print('Configuracion privada preparada.')
