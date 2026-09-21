from __future__ import annotations
import csv, json, logging, random, time
from pathlib import Path
from typing import Any, Iterable
from .utils import append_jsonl, stable_id, utc_now

log = logging.getLogger(__name__)
REQUIRED = {'timestamp', 'source', 'event_type', 'src_ip', 'action', 'status'}


def normalize_event(raw: dict[str, Any], source_hint: str | None = None) -> dict[str, Any]:
    missing = REQUIRED - set(raw)
    if missing: raise ValueError(f'missing required fields: {sorted(missing)}')
    event = {
        'event_id': stable_id(json.dumps(raw, sort_keys=True)),
        'ingested_at': utc_now(),
        'timestamp': raw['timestamp'], 'source': source_hint or raw['source'],
        'event_type': raw['event_type'], 'username': raw.get('username', 'unknown'),
        'src_ip': raw.get('src_ip'), 'dst_ip': raw.get('dst_ip'),
        'action': raw['action'], 'status': raw['status'],
        'bytes': float(raw.get('bytes', 0) or 0), 'duration_ms': float(raw.get('duration_ms', 0) or 0),
        'country': raw.get('country', 'Unknown'), 'domain': raw.get('domain'), 'sha256': raw.get('sha256'),
        'raw': raw,
    }
    return event


def load_records(path: str) -> Iterable[dict[str, Any]]:
    p = Path(path)
    if p.suffix.lower() == '.csv':
        with p.open(newline='', encoding='utf-8') as f: yield from csv.DictReader(f)
    else:
        for line in p.read_text(encoding='utf-8').splitlines():
            if line.strip(): yield json.loads(line)


def ingest_file(path: str, output: str) -> list[dict[str, Any]]:
    seen, events = set(), []
    for raw in load_records(path):
        event = normalize_event(raw)
        if event['event_id'] not in seen:
            append_jsonl(output, event); events.append(event); seen.add(event['event_id'])
    log.info('ingested=%s output=%s', len(events), output)
    return events


def simulate_stream(count: int = 20, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    actions = ['login_success', 'login_failed', 'port_scan', 'dns_tunnel', 'file_download']
    result = []
    for i in range(count):
        action = rng.choice(actions)
        result.append(normalize_event({'timestamp': utc_now(), 'source': 'stream-simulator', 'event_type': 'stream', 'username': f'user-{i%5}', 'src_ip': f'10.0.0.{rng.randint(2, 250)}', 'dst_ip': '10.0.0.10', 'action': action, 'status': 'failure' if 'failed' in action else 'allowed', 'bytes': rng.randint(200, 100000) if action != 'dns_tunnel' else rng.randint(100000, 500000), 'duration_ms': rng.randint(20, 3000), 'country': rng.choice(['PK','US','DE','NL'])}))
        time.sleep(0.01)
    return result
