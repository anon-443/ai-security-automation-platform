# SentinelForge AI Security Automation Platform

**Advanced Track Week 10 Capstone — Adeen Shahzad**

SentinelForge is an integrated, offline-first security operations platform combining normalized telemetry ingestion, threat-intelligence enrichment, machine-learning anomaly detection, confidence-based SOAR orchestration, case management, and an interactive Streamlit dashboard.

## What is included

- Multi-source ingestion: JSON/CSV/line-oriented logs, REST endpoints, and deterministic streaming simulation.
- Common event schema with validation, deduplication, source metadata, and processing timestamps.
- Threat intelligence adapters for VirusTotal, AbuseIPDB, and AlienVault OTX with TTL JSON caching and safe offline fallback.
- Week 5 pretrained Isolation Forest and StandardScaler artifacts integrated against the original `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, and `rate` feature contract, plus a supervised Random Forest classifier for the capstone confidence layer.
- SOAR policies with automated high-confidence playbooks, analyst approval for medium confidence, notification audit records, and case management.
- Streamlit + Plotly dashboard with KPIs, alert timeline, confidence distribution, threat map, event drill-down, analyst queue, and playbook status.
- Architecture and engineering review documents, tests, sample data, a resume update, and presentation source.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python platform.py --mode full --input data/sample_logs.jsonl
streamlit run dashboard.py
```

The full mode writes evidence to `runtime/` and uses no external API keys by default. Optional live TI keys can be placed in environment variables (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `OTX_API_KEY`). Never commit real secrets.

The Week 5 artifacts are stored in `models/week5/` and are loaded automatically by the ML detector. If those artifacts are unavailable, the detector has a documented synthetic fallback for portability.

## Commands

```bash
python platform.py --mode ingest --input data/sample_logs.jsonl
python platform.py --mode enrich
python platform.py --mode detect
python platform.py --mode soar
python platform.py --mode full --input data/sample_logs.jsonl
python platform.py --mode stream --events 20
pytest -q
streamlit run dashboard.py
```

## Security and reliability controls

The default profile is safe for demos: API failures degrade to cached/offline intelligence, all actions are logged, secrets are environment-only, input is schema-validated, and SOAR actions are simulated rather than destructive. Production deployment should place the API behind TLS, SSO/RBAC, a secrets manager, a real queue, and a transactional database.

See `docs/data_flow.md`, `docs/tech_stack.md`, `docs/integration_plan.md`, and `docs/engineering_review.md` for the complete engineering narrative.
