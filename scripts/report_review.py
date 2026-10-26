"""Summarize observed local tests and verify HOLD against real queue IDs."""
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

compose = ['docker', 'compose', '-f', 'compose.yaml', '-f', 'compose.gpu.yaml', '-f', 'compose.mail.yaml']
def docker(*args):
    return subprocess.check_output(compose + list(args), text=True, encoding='utf-8')

root = Path('results')
queue_text = docker('exec', '-T', 'mailserver', 'postqueue', '-j')
(root / 'review-queue-final.jsonl').write_text(queue_text, encoding='utf-8')
queue = [json.loads(line) for line in queue_text.splitlines() if line.strip()]
held = {row['queue_id'] for row in queue if row['queue_name'] == 'hold'}
events = []
for name in ('mail-filtered.json', 'mail-filtered-reverse.json', 'greetings.json'):
    events.extend(json.loads((root / 'review-mail' / name).read_text(encoding='utf-8')))
audits = [json.loads(path.read_text(encoding='utf-8')) for path in (root / 'mail').glob('*.json')]
matches = []
for event in events:
    match = [audit for audit in audits if audit['static']['headers'].get('Message-ID') == event['message_id']]
    assert len(match) == 1, ('Expected one audit', event['message_id'])
    audit = match[0]
    delivered = event.get('expected_inbox', True)
    assert event['observed_inbox_count'] == int(delivered)
    assert (audit['queue_id'] in held) == (not delivered)
    matches.append({'message_id': event['message_id'], 'queue_id': audit['queue_id'], 'decision': audit['decision'], 'ai_status': audit['ai']['status'], 'inbox_count': event['observed_inbox_count'], 'in_postfix_hold': audit['queue_id'] in held})
outage = json.loads((root / 'review-mail/mail-outage.json').read_text())[0]
assert outage['observed_inbox_count'] == 0
# Mailserver applies its own quarantine if it cannot connect to our Milter.
outage_held = []
for queue_id in held:
    contents = docker('exec', '-T', 'mailserver', 'postcat', '-q', queue_id)
    if outage['message_id'] in contents:
        outage_held.append(queue_id)
assert len(outage_held) == 1
baseline = {'4C3FFBC1E', '2526B10577', 'B1C6B1097B', 'B4EC98A5F', 'B109310B35', '1911A10B82'}
assert baseline <= held, 'An original HOLD message is missing'
assert not [row for row in queue if row['queue_name'] == 'deferred'], 'Deferred messages remain'
rows = [json.loads(path.read_text()) for path in sorted((root / 'review-real').glob('*.json'))]
assert len(rows) == 6
binary = [row for row in rows if row['classification'] != 'indeterminado']
metrics = {
    'n': len(rows), 'ai_valid': sum(row['ai']['status'] == 'ok' for row in rows),
    'ai_abstentions': len(rows) - len(binary),
    'ai_tp': sum(row['classification'] == row['expected'] == 'sospechoso' for row in binary),
    'ai_tn': sum(row['classification'] == row['expected'] == 'sin_indicios_suficientes' for row in binary),
    'ai_fp': sum(row['classification'] == 'sospechoso' and row['expected'] == 'sin_indicios_suficientes' for row in binary),
    'ai_fn': sum(row['classification'] == 'sin_indicios_suficientes' and row['expected'] == 'sospechoso' for row in binary),
    'ai_coverage': len(binary) / len(rows),
    'abstention_rule': 'Abstentions excluded from binary confusion counts, explicitly reported; never counted as correct.',
    'policy_correct_synthetic_cases': sum((row['decision'] == 'cuarentena') == (row['expected'] == 'sospechoso') for row in rows),
    'limitations': 'Six synthetic functional examples; no estimate of general detection performance.',
}
services = [json.loads(line) for line in docker('ps', '--format', 'json').splitlines() if line.strip()]
assert len(services) == 3 and all(service.get('Health') == 'healthy' for service in services)
summary = {'timestamp': datetime.now(timezone.utc).isoformat(), 'services': services, 'smtp_imap_events': matches, 'outage': {'message_id': outage['message_id'], 'queue_id': outage_held[0], 'inbox_count': 0, 'in_postfix_hold': True}, 'old_hold_messages_preserved': sorted(baseline), 'deferred_messages': 0, 'metrics': metrics, 'external_reputation': 'Disabled: no keys or opt-in supplied', 'thunderbird': 'Both accounts configured; online status and received messages verified in UI. Send-button verification blocked by detected user input.'}
(root / 'review-summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
(root / 'review-services.txt').write_text(docker('ps'), encoding='utf-8')
(root / 'review-milter-config.txt').write_text(docker('exec', '-T', 'mailserver', 'postconf', 'smtpd_milters', 'non_smtpd_milters', 'milter_default_action', 'milter_content_timeout'), encoding='utf-8')
print(json.dumps({'services_healthy': len(services), 'verified_smtp_imap_cases': len(matches), 'outage_hold_verified': outage_held, 'old_hold_preserved': len(baseline), 'metrics': metrics}, indent=2))
