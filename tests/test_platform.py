import json
from pathlib import Path
from sentinelforge.ingest_logs import normalize_event
from sentinelforge.ti_enricher import ThreatIntelEnricher
from sentinelforge.ml_detector import MLDetector

def cfg(tmp_path):
    return {'storage':{'cache_file':str(tmp_path/'cache.jsonl'),'runtime_dir':str(tmp_path)},'threat_intelligence':{'cache_ttl_seconds':100,'offline_mode':True,'request_timeout_seconds':1},'ml':{'model_dir':str(tmp_path/'models'),'contamination':.1,'random_state':42,'retrain':True}}

def test_normalization_is_stable():
    raw={'timestamp':'2026-01-01T00:00:00Z','source':'x','event_type':'auth','src_ip':'1.2.3.4','action':'login_failed','status':'failure'}
    a=normalize_event(raw); b=normalize_event(raw); assert a['event_id']==b['event_id']; assert a['bytes']==0

def test_offline_ti_cache(tmp_path):
    c=cfg(tmp_path); e=ThreatIntelEnricher(c); x=e.lookup('185.220.101.7'); y=e.lookup('185.220.101.7'); assert x['score']>.8 and y['indicator']==x['indicator']

def test_detector_produces_confidence(tmp_path):
    c=cfg(tmp_path); d=MLDetector(c); event=normalize_event({'timestamp':'2026-01-01T00:00:00Z','source':'x','event_type':'network','src_ip':'185.220.101.7','action':'port_scan','status':'blocked','bytes':100000,'duration_ms':3000}); event['ti_score']=.9; out=d.score(event); assert 0<=out['confidence']<=1; assert out['prediction']=='threat'
