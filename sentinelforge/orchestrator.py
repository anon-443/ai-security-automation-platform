from __future__ import annotations
import argparse
from .utils import load_config, ensure_runtime, read_jsonl, setup_logging, append_jsonl
from .ingest_logs import ingest_file, simulate_stream
from .ti_enricher import enrich_events
from .ml_detector import detect_events
from .soar_engine import run_soar

def main():
    p=argparse.ArgumentParser(description='SentinelForge end-to-end security automation platform')
    p.add_argument('--mode',choices=['ingest','enrich','detect','soar','full','stream'],default='full'); p.add_argument('--input',default='data/sample_logs.jsonl'); p.add_argument('--events',type=int,default=20); p.add_argument('--config',default='config.yaml')
    args=p.parse_args(); cfg=load_config(args.config); setup_logging(cfg['app']['log_level']); ensure_runtime(cfg); s=cfg['storage']
    if args.mode=='ingest': ingest_file(args.input,s['events_file'])
    elif args.mode=='enrich': enrich_events(read_jsonl(s['events_file']),cfg,s['enriched_file'])
    elif args.mode=='detect': detect_events(read_jsonl(s['enriched_file']),cfg,s['alerts_file'])
    elif args.mode=='soar': run_soar(read_jsonl(s['alerts_file']),cfg,s['cases_file'].replace('cases','soar_results'))
    elif args.mode=='stream':
        events=simulate_stream(args.events); [append_jsonl(s['events_file'],e) for e in events]; rows=enrich_events(events,cfg,s['enriched_file']); alerts=detect_events(rows,cfg,s['alerts_file']); run_soar(alerts,cfg,s['cases_file'].replace('cases','soar_results'))
    else:
        events=ingest_file(args.input,s['events_file']); rows=enrich_events(events,cfg,s['enriched_file']); alerts=detect_events(rows,cfg,s['alerts_file']); cases=run_soar(alerts,cfg,s['cases_file'].replace('cases','soar_results')); print(f'Pipeline complete: ingested={len(events)} enriched={len(rows)} alerts={len(alerts)} cases={len(cases)}')

if __name__=='__main__': main()
