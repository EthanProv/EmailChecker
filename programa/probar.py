"""Prueba local: correo normal, enlace enganoso y bloqueo de envios sin autenticar."""
import imaplib
import json
import smtplib
import ssl
import subprocess
import time
import uuid
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

# Se ejecuta dentro del servidor: aqui ya estan sus herramientas y cuentas.
cuentas = json.loads(Path('credentials.json').read_text(encoding='utf-8'))
tls = ssl.create_default_context(cafile='cert.pem')
ejemplos = [('Hola equipo. Nos vemos manana para revisar el informe. Gracias.', True),
            ('<a href="https://falso.example">https://banco.example</a>', False)]
direcciones = [('docente@empresa.lab', 'alumno@empresa.lab'),
               ('alumno@empresa.lab', 'docente@empresa.lab')]

for origen, destino in direcciones:
    for contenido, debe_llegar in ejemplos:
        correo = EmailMessage()
        correo['From'], correo['To'] = origen, destino
        correo['Subject'] = 'Prueba de correo'
        correo['Date'] = formatdate(localtime=True)
        correo['Message-ID'] = '<' + uuid.uuid4().hex + '@empresa.lab>'
        correo.set_content(contenido, subtype='plain' if debe_llegar else 'html')
        with smtplib.SMTP_SSL('localhost', 465, context=tls, timeout=60) as smtp:
            smtp.login(origen, cuentas[origen])
            smtp.send_message(correo)
        with imaplib.IMAP4_SSL('localhost', 993, ssl_context=tls, timeout=20) as inbox:
            inbox.login(destino, cuentas[destino])
            inbox.select('INBOX', readonly=True)
            cantidad = 0
            for intento in range(10):
                inbox.noop()
                estado, datos = inbox.search(None, 'HEADER', 'Message-ID', '"' + correo['Message-ID'] + '"')
                if estado != 'OK':
                    raise ValueError('No se pudo consultar la bandeja.')
                cantidad = len(datos[0].split())
                if cantidad:
                    break
                time.sleep(1)
        if cantidad != int(debe_llegar):
            raise ValueError('El correo no llego como se esperaba.')
        if not debe_llegar:
            retenido = False
            for linea in subprocess.check_output(['postqueue', '-j'], text=True).splitlines():
                fila = json.loads(linea)
                if fila['queue_name'] == 'hold':
                    mensaje = subprocess.check_output(['postcat', '-q', fila['queue_id']], text=True)
                    if correo['Message-ID'] in mensaje:
                        retenido = True
                        break
            if not retenido:
                raise ValueError('No se encontro el correo en cuarentena.')
        print(origen + ' -> ' + destino + ': comprobado', flush=True)

with smtplib.SMTP('localhost', 587, timeout=20) as smtp:
    smtp.starttls(context=tls)
    smtp.mail('outsider@external.example')
    codigo, respuesta = smtp.rcpt('victim@external.example')
    if codigo < 500:
        raise ValueError('Se permiten envios externos sin autenticacion.')
print('Entrega, cuarentena y autenticacion comprobadas.', flush=True)
