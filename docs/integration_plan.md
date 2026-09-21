# Integration Plan

## Interfaces

- `ingest_logs.py` exposes `normalize_event`, `ingest_file`, and `simulate_stream`.
- `ti_enricher.py` exposes `ThreatIntelEnricher.lookup` and `enrich`.
- `ml_detector.py` exposes `MLDetector.score` and `detect_events`.
- `soar_engine.py` exposes `SOAREngine.process` and `run_soar`.
- `platform.py` composes the stages through `--mode full`.

## External services

Threat-intelligence credentials are read only from environment variables. The service boundary normalizes provider-specific response formats into `{indicator, score, band, sources}`. Provider errors are logged and handled by cache/offline fallback. Future connectors can publish alerts to email, Slack, Jira, ServiceNow, or a SIEM without changing the detector contract.

## Security controls

The platform follows least privilege by default: no destructive endpoint action is executed, secrets are not stored in YAML, request timeouts are bounded, raw payloads are retained for evidence, and all automated decisions create audit records. A production service must add authentication, authorization, encryption in transit/at rest, rate limiting, input size limits, dependency scanning, and signed model artifacts.

## Scalability

The current pipeline is single-process and append-oriented for clarity. At 10x volume, partition ingestion by source, publish normalized events to Kafka, run stateless enrichment/detection workers horizontally, store features in a time-series database, and move case transitions into transactional APIs. Cache keys and model inference are already isolated enough to support that evolution.
