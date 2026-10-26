import argparse
import csv
import hashlib
import json
import time
from pathlib import Path
from .parser import parse, MAX_MESSAGE
from .ai import analyze
from .policy import decide
from .reputation import Reputation

def run(path, reputation):
    start = time.monotonic()
    with path.open('rb') as stream:
        raw = stream.read(MAX_MESSAGE + 1)
    static = parse(raw)
    ai = analyze(static) if not static['incomplete'] else {'status': 'skipped_incomplete', 'classification': 'indeterminado', 'reasons': [], 'evidence': []}
    rep = reputation.analyze(static)
    decision, reasons = decide(static, ai, rep)
    return {'id': path.stem, 'message_sha256': hashlib.sha256(raw).hexdigest() if len(raw) <= MAX_MESSAGE else None,
            'expected': None, 'classification': ai['classification'], 'decision': decision, 'reasons': reasons,
            'seconds': round(time.monotonic() - start, 3), 'static': static, 'ai': ai, 'reputation': rep,
            'policy_version': 'academic-v1', 'execution': 'real_local_inference', 'intercepts_delivery': False}

def main():
    cli = argparse.ArgumentParser()
    cli.add_argument('eml', nargs='?', type=Path)
    cli.add_argument('--batch', type=Path)
    cli.add_argument('--output', type=Path, default=Path('results/real'))
    args = cli.parse_args()
    if not args.eml and not args.batch:
        cli.error('Indica archivo .eml o --batch carpeta')
    args.output.mkdir(parents=True, exist_ok=True)
    expected_file = args.batch / 'expected.json' if args.batch else None
    expected = json.loads(expected_file.read_text(encoding='utf-8')) if expected_file and expected_file.exists() else {}
    reputation = Reputation()
    results = []
    try:
        for path in sorted(args.batch.glob('*.eml')) if args.batch else [args.eml]:
            result = run(path, reputation)
            result['expected'] = expected.get(path.stem)
            (args.output / (path.stem + '.json')).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
            results.append(result)
            print(json.dumps({k: result[k] for k in ('id', 'classification', 'decision', 'seconds')}, ensure_ascii=False), flush=True)
    finally:
        reputation.db.close()
    with (args.output / 'summary.csv').open('w', encoding='utf-8-sig', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['id', 'expected', 'classification', 'decision', 'reasons', 'seconds', 'ai_status', 'reputation_status', 'model', 'model_digest', 'config'])
        writer.writeheader()
        for r in results:
            writer.writerow({**{k: r[k] for k in ('id', 'expected', 'classification', 'decision', 'seconds')}, 'reasons': ' | '.join(r['reasons']),
                             'ai_status': r['ai']['status'], 'reputation_status': r['reputation']['status'], 'model': r['ai'].get('model'),
                             'model_digest': r['ai'].get('model_digest'), 'config': json.dumps(r['ai'].get('config'))})

if __name__ == '__main__':
    main()
