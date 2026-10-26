"""Real local SMTP/IMAP regression check for newline-containing short mail."""
import imaplib
import json
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

context = ssl.create_default_context(cafile='mail-config/cert.pem')
credentials = json.loads(Path('mail-config/credentials.json').read_text())
events = []
for sender, recipient, text in [('docente@empresa.lab', 'alumno@empresa.lab', 'Prueba v2\r\n\r\n\r\n'), ('alumno@empresa.lab', 'docente@empresa.lab', 'Perfecto\r\n\r\n')]:
    message = EmailMessage()
    message['From'], message['To'] = sender, recipient
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = '<' + uuid.uuid4().hex + '@empresa.lab>'
    message.set_content(text)
    with smtplib.SMTP_SSL('127.0.0.1', 465, context=context, timeout=60) as smtp:
        smtp.login(sender, credentials[sender])
        smtp.send_message(message)
    with imaplib.IMAP4_SSL('127.0.0.1', 1993, ssl_context=context, timeout=15) as inbox:
        inbox.login(recipient, credentials[recipient])
        inbox.select('INBOX', readonly=True)
        for attempt in range(15):
            inbox.noop()
            status, data = inbox.search(None, 'HEADER', 'Message-ID', '"' + message['Message-ID'] + '"')
            assert status == 'OK'
            count = len(data[0].split())
            if count:
                break
            time.sleep(1)
    event = {'message_id': message['Message-ID'], 'text': text, 'sender': sender, 'recipient': recipient, 'observed_inbox_count': count}
    events.append(event)
    print(json.dumps(event), flush=True)
    Path('results/review-mail/greetings.json').write_text(json.dumps(events, ensure_ascii=False, indent=2), encoding='utf-8')
    assert count == 1, 'Short legitimate message was not delivered exactly once'
