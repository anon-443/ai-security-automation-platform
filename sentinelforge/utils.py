from __future__ import annotations
import hashlib, json, logging, os, re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import yaml


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def load_config(path: str = 'config.yaml') -> dict[str, Any]:
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f)


def setup_logging(level: str = 'INFO') -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format='%(asctime)s %(levelname)s %(name)s %(message)s')


def ensure_runtime(cfg: dict[str, Any]) -> None:
    Path(cfg['storage']['runtime_dir']).mkdir(parents=True, exist_ok=True)
    Path(cfg['ml']['model_dir']).mkdir(parents=True, exist_ok=True)


def append_jsonl(path: str, record: dict[str, Any]) -> None:
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, sort_keys=True) + '\n')


def read_jsonl(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists(): return []
    rows = []
    for line in p.read_text(encoding='utf-8').splitlines():
        if line.strip(): rows.append(json.loads(line))
    return rows


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def is_ip(value: str) -> bool:
    return bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', value or ''))


def risk_band(score: float) -> str:
    return 'critical' if score >= .85 else 'high' if score >= .65 else 'medium' if score >= .35 else 'low'
