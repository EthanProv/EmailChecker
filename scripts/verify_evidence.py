"""Read observed artifacts; never substitute expected labels for observations."""
import json
from pathlib import Path

before = [json.loads(line) for line in Path('results/postfix-queue-before-restart.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
after = [json.loads(line) for line in Path('results/postfix-queue-after-restart.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
held_before = {x['queue_id'] for x in before if x['queue_name'] == 'hold'}
held_after = {x['queue_id'] for x in after if x['queue_name'] == 'hold'}
assert held_before and held_before <= held_after
rows = [json.loads(p.read_text(encoding='utf-8')) for p in sorted(Path('results/final').glob('*.json'))]
assert len(rows) == 6
summary = {
    'real_local_inferences': len(rows),
    'ai_status_ok': sum(r['ai']['status'] == 'ok' for r in rows),
    'ai_indeterminate': sum(r['classification'] == 'indeterminado' for r in rows),
    'decisions': {decision: sum(r['decision'] == decision for r in rows) for decision in ('permitir', 'cuarentena', 'pendiente de revisión')},
    'hold_persisted_ids': sorted(held_before),
    'limitations': 'Seis muestras sintéticas; no demuestra eficacia general. Reputación externa no ejecutada.'
}
Path('results/verification-summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
print(json.dumps(summary, ensure_ascii=False, indent=2))
