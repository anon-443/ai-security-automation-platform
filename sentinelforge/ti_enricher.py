from __future__ import annotations
import hashlib, logging, os, time
from typing import Any
import requests
from .utils import append_jsonl, read_jsonl, risk_band, utc_now

log = logging.getLogger(__name__)

class ThreatIntelEnricher:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.cache_file = cfg['storage']['cache_file']
        self.ttl = cfg['threat_intelligence']['cache_ttl_seconds']
        self.offline = cfg['threat_intelligence'].get('offline_mode', True)
        self.cache = {r['indicator']: r for r in read_jsonl(self.cache_file)}

    def _offline_lookup(self, indicator: str) -> dict[str, Any]:
        digest = int(hashlib.sha256(indicator.encode()).hexdigest()[:8], 16)
        suspicious = any(x in indicator.lower() for x in ['185.220', '203.0.113', '198.51.100', 'suspicious', 'exfil', 'e3b0c4'])
        score = 0.88 if suspicious else round(0.08 + (digest % 24) / 100, 2)
        return {'indicator': indicator, 'score': score, 'band': risk_band(score), 'malicious_votes': int(score*20), 'sources': ['offline-demo'], 'last_seen': utc_now()}

    def _live_lookup(self, indicator: str) -> dict[str, Any] | None:
        headers = {}; url = None
        if os.getenv('OTX_API_KEY'):
            headers = {'X-OTX-API-KEY': os.environ['OTX_API_KEY']}
            url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general'
            try:
                r = requests.get(url, headers=headers, timeout=self.cfg['threat_intelligence']['request_timeout_seconds'])
                r.raise_for_status()
                d = r.json()
                pulses = int(d.get('pulse_info', {}).get('count', 0))
                score = min(1.0, pulses / 10.0)
                return {'indicator': indicator, 'score': score, 'band': risk_band(score), 'malicious_votes': pulses, 'sources': ['alienvault-otx'], 'last_seen': utc_now()}
            except requests.RequestException as e:
                log.warning('AlienVault OTX unavailable: %s', e)
                return None
        if os.getenv('VIRUSTOTAL_API_KEY'):
            headers = {'x-apikey': os.environ['VIRUSTOTAL_API_KEY']}; url = f'https://www.virustotal.com/api/v3/ip_addresses/{indicator}'
        elif os.getenv('ABUSEIPDB_API_KEY'):
            headers = {'Key': os.environ['ABUSEIPDB_API_KEY'], 'Accept': 'application/json'}; url = 'https://api.abuseipdb.com/api/v2/check';
            try:
                r = requests.get(url, headers=headers, params={'ipAddress': indicator}, timeout=self.cfg['threat_intelligence']['request_timeout_seconds']); r.raise_for_status(); d=r.json().get('data', {}); score=float(d.get('abuseConfidenceScore',0))/100; return {'indicator':indicator,'score':score,'band':risk_band(score),'malicious_votes':d.get('totalReports',0),'sources':['abuseipdb'],'last_seen':utc_now()}
            except requests.RequestException as e: log.warning('AbuseIPDB unavailable: %s', e); return None
        if not url: return None
        try:
            r=requests.get(url, headers=headers, timeout=self.cfg['threat_intelligence']['request_timeout_seconds']); r.raise_for_status(); d=r.json().get('data', {}).get('attributes', {}); score=float(d.get('reputation',0)); score=max(0,min(1,score/100)); return {'indicator':indicator,'score':score,'band':risk_band(score),'malicious_votes':d.get('last_analysis_stats',{}).get('malicious',0),'sources':['virustotal'],'last_seen':utc_now()}
        except requests.RequestException as e: log.warning('VirusTotal unavailable: %s', e); return None

    def lookup(self, indicator: str) -> dict[str, Any]:
        cached = self.cache.get(indicator)
        if cached and time.time() - cached.get('_cached_epoch', 0) < self.ttl: return cached
        result = None if self.offline else self._live_lookup(indicator)
        result = result or self._offline_lookup(indicator)
        result['_cached_epoch'] = time.time(); self.cache[indicator] = result; append_jsonl(self.cache_file, result)
        return result

    def enrich(self, event: dict[str, Any]) -> dict[str, Any]:
        indicators = [x for x in [event.get('src_ip'), event.get('domain'), event.get('sha256')] if x]
        intel = [self.lookup(x) for x in indicators]
        max_score = max([i['score'] for i in intel], default=0.0)
        return {**event, 'threat_intelligence': intel, 'ti_score': round(max_score, 3), 'ti_band': risk_band(max_score), 'enriched_at': utc_now()}

def enrich_events(events: list[dict[str, Any]], cfg: dict[str, Any], output: str) -> list[dict[str, Any]]:
    enricher=ThreatIntelEnricher(cfg); rows=[]
    for event in events:
        row=enricher.enrich(event); append_jsonl(output,row); rows.append(row)
    return rows
