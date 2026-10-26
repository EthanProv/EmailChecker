"""Load the local model before accepting Milter connections."""
import os
from urllib.parse import urlsplit
from .ai import request

def warmup():
    base = os.getenv('OLLAMA_URL', 'http://localhost:11434')
    model = os.getenv('OLLAMA_MODEL', 'qwen3:4b')
    if urlsplit(base).hostname not in ('ollama', 'localhost', '127.0.0.1', '::1') or ':cloud' in model or model.endswith('-cloud'):
        raise ValueError('nonlocal_endpoint_or_model_rejected')
    return request(base, '/api/generate', {'model': model, 'stream': False, 'keep_alive': '24h', 'options': {'num_ctx': 8192}}, timeout=180)

if __name__ == '__main__':
    warmup()
    print('Modelo local precargado; keep_alive=24h.', flush=True)
