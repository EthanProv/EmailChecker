"""Minimal Milter v6: explicit quarantine in Postfix HOLD, no reinjection.

Bounded serial server for a local academic lab, not a production Milter.
"""
import hashlib
import json
import os
import socketserver
import struct
import time
from pathlib import Path
from .parser import parse, MAX_MESSAGE
from .ai import analyze
from .policy import decide

class Handler(socketserver.StreamRequestHandler):
    timeout = 40

    def send(self, command, data=b''):
        self.wfile.write(struct.pack('!I', len(data) + 1) + command + data)
        self.wfile.flush()

    def handle(self):
        raw, macros, envelope = bytearray(), {}, []
        too_large = False
        while True:
            header = self.rfile.read(4)
            if not header:
                return
            if len(header) != 4:
                return
            size = struct.unpack('!I', header)[0]
            if not 1 <= size <= MAX_MESSAGE + 1:
                return
            packet = self.rfile.read(size)
            if len(packet) != size:
                return
            command, data = packet[:1], packet[1:]
            if command == b'O':
                version, actions, protocol = struct.unpack('!III', data)
                if not actions & 0x20:
                    return
                self.send(b'O', struct.pack('!III', min(version, 6), 0x20, 0))
                continue
            if command == b'D':
                pairs = data[1:].rstrip(b'\0').split(b'\0')
                macros.update({pairs[i].decode(errors='replace'): pairs[i+1].decode(errors='replace') for i in range(0, len(pairs)-1, 2)})
                continue
            if command == b'Q':
                return
            if command == b'A':
                raw, envelope, too_large = bytearray(), [], False
                continue
            if command == b'M':
                raw, envelope, too_large = bytearray(), [data.split(b'\0')[0].decode(errors='replace')], False
            elif command == b'R':
                envelope.append(data.split(b'\0')[0].decode(errors='replace'))
            elif command == b'L':
                key, value = data.rstrip(b'\0').split(b'\0', 1)
                if len(raw) + len(data) <= MAX_MESSAGE:
                    raw.extend(key + b': ' + value + b'\r\n')
                else:
                    too_large = True
            elif command == b'N':
                raw.extend(b'\r\n')
            elif command == b'B':
                if len(raw) + len(data) <= MAX_MESSAGE:
                    raw.extend(data)
                else:
                    too_large = True
            elif command == b'E':
                start = time.monotonic()
                try:
                    parsed = parse(bytes(raw))
                    if too_large:
                        parsed['incomplete'].append('message_size_limit')
                    ai = analyze(parsed) if not parsed['incomplete'] else {'status': 'skipped_incomplete', 'classification': 'indeterminado'}
                    rep = {'status': 'disabled_demo', 'items': []}
                    decision, reasons = decide(parsed, ai, rep)
                    digest = hashlib.sha256(raw).hexdigest()
                    event = {'queue_id': macros.get('i', macros.get('{i}', 'unknown')), 'sha256': digest,
                             'envelope': envelope, 'decision': decision, 'reasons': reasons, 'ai': ai,
                             'static': parsed, 'reputation': rep, 'seconds': time.monotonic() - start,
                             'intercepts_delivery': True, 'quarantine_backend': 'Postfix HOLD', 'timestamp': time.time()}
                    folder = Path('results/mail')
                    folder.mkdir(parents=True, exist_ok=True)
                    target = folder / (str(time.time_ns()) + '-' + digest[:12] + '.json')
                    with target.open('x', encoding='utf-8') as file:
                        json.dump(event, file, ensure_ascii=False, indent=2)
                        file.flush()
                        os.fsync(file.fileno())
                    if decision != 'permitir':
                        self.send(b'q', ('academic-v1 ' + decision + ' audit=' + target.name).encode() + b'\0')
                    self.send(b'c')
                    print(json.dumps({k: event[k] for k in ('queue_id', 'decision', 'seconds')}), flush=True)
                except Exception as exc:
                    print(type(exc).__name__, flush=True)
                    self.send(b't')
                continue
            self.send(b'c')

class Server(socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 5

if __name__ == '__main__':
    from .warmup import warmup
    try:
        warmup()
        print('Local model ready; keep_alive=24h', flush=True)
    except Exception as exc:
        # Keep the fail-closed filter available even if the model cannot load.
        print('Model warmup unavailable: ' + type(exc).__name__, flush=True)
    with Server(('0.0.0.0', 9900), Handler) as server:
        server.serve_forever()
