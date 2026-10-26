import io
import json
import struct
import unittest
from unittest.mock import patch
from antiphishing.milter import Handler

def packet(command, data=b''):
    return struct.pack('!I', len(data) + 1) + command + data

class MilterTests(unittest.TestCase):
    def run_protocol(self, classification):
        handler = Handler.__new__(Handler)
        handler.rfile = io.BytesIO(packet(b'O', struct.pack('!III', 6, 0x20, 0)) + packet(b'M', b'<a@empresa.lab>\0') + packet(b'L', b'Subject\0Test\0') + packet(b'N') + packet(b'B', b'Hola') + packet(b'E') + packet(b'Q'))
        handler.wfile = io.BytesIO()
        ai = {'status': 'ok', 'classification': classification, 'reasons': ['SIMULATED TEST']}
        # Only this test mocks inference and audit file operations.
        with patch('antiphishing.milter.analyze', return_value=ai), patch('antiphishing.milter.Path') as path, patch('antiphishing.milter.os.fsync'):
            path.return_value.__truediv__.return_value.name = 'SIMULATED.json'
            handler.handle()
        output = io.BytesIO(handler.wfile.getvalue())
        commands = []
        while prefix := output.read(4):
            commands.append(output.read(struct.unpack('!I', prefix)[0])[:1])
        return commands

    def test_hold_action(self):
        self.assertEqual(self.run_protocol('sospechoso')[-2:], [b'q', b'c'])

    def test_allow_without_reinjection(self):
        self.assertNotIn(b'q', self.run_protocol('sin_indicios_suficientes'))
