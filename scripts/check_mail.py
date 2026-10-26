import argparse
import imaplib
import json
import smtplib
import ssl
import time
import uuid
from email import policy
from email.parser import BytesParser
from email.utils import formatdate
from pathlib import Path

cli = argparse.ArgumentParser()
cli.add_argument('--phase', choices=['baseline', 'filtered', 'outage'], required=True)
cli.add_argument('--smtp', choices=['starttls', 'smtps'], default='smtps')
cli.add_argument('--output', type=Path, default=Path('results'))
cli.add_argument('--reverse', action='store_true', help='Send from alumno to docente')
args = cli.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
sender, recipient = ('alumno@empresa.lab', 'docente@empresa.lab') if args.reverse else ('docente@empresa.lab', 'alumno@empresa.lab')
credentials = json.loads(Path('mail-config/credentials.json').read_text())
context = ssl.create_default_context(cafile='mail-config/cert.pem')
events = []
cases = [('01_legitimate', True)] if args.phase == 'baseline' else [('01_legitimate', True), ('04_mismatch', False)]
if args.phase == 'outage':
    cases = [('01_legitimate', False)]
for name, expect_delivery in cases:
    msg = BytesParser(policy=policy.SMTP).parsebytes(Path('samples', name + '.eml').read_bytes())
    msg.replace_header('From', sender)
    msg.replace_header('To', recipient)
    if 'Date' in msg:
        del msg['Date']
    msg['Date'] = formatdate(localtime=True)
    msg.replace_header('Message-ID', '<' + uuid.uuid4().hex + '@empresa.lab>')
    del msg['Return-Path']
    del msg['Reply-To']
    message_id = str(msg['Message-ID'])
    start = time.monotonic()
    connection = smtplib.SMTP_SSL('127.0.0.1', 465, context=context, timeout=60) if args.smtp == 'smtps' else smtplib.SMTP('127.0.0.1', 1587, timeout=60)
    with connection as smtp:
        if args.smtp == 'starttls':
            smtp.starttls(context=context)
        smtp.login(sender, credentials[sender])
        smtp.sendmail(sender, [recipient], msg.as_bytes())
    count = 0
    with imaplib.IMAP4_SSL('localhost', 1993, ssl_context=context) as imap:
        imap.login(recipient, credentials[recipient])
        imap.select('INBOX', readonly=True)
        for attempt in range(10):
            imap.noop()
            status, data = imap.search(None, 'HEADER', 'Message-ID', '"' + message_id + '"')
            assert status == 'OK'
            count = len(data[0].split())
            if count:
                break
            time.sleep(1)
    event = {'phase': args.phase, 'sample': name, 'message_id': message_id, 'sender': sender, 'recipient': recipient, 'smtp': args.smtp, 'expected_inbox': expect_delivery, 'observed_inbox_count': count, 'seconds': round(time.monotonic() - start, 3)}
    events.append(event)
    print(json.dumps(event), flush=True)
    (args.output / ('mail-' + args.phase + ('-reverse' if args.reverse else '') + '.json')).write_text(json.dumps(events, indent=2), encoding='utf-8')
    assert count == (1 if expect_delivery else 0), 'Unexpected delivery count'
with smtplib.SMTP('localhost', 1587, timeout=20) as smtp:
    smtp.starttls(context=context)
    smtp.ehlo()
    smtp.mail('outsider@external.example')
    code, response = smtp.rcpt('victim@external.example')
    assert code >= 500, 'Unauthenticated external relay was not rejected'
    (args.output / 'relay-check.txt').write_text(str(code) + ' ' + response.decode(), encoding='utf-8')
print('TLS, SMTP, IMAP, recuento y rechazo de relay comprobados.')
