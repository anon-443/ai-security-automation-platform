# Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.11+ | Strong security, data, ML, and automation ecosystem. |
| Ingestion | JSONL, CSV, `requests`, pandas-compatible records | Simple local reproducibility plus clear path to REST and streaming sources. |
| Storage | JSONL evidence files + TTL JSON cache | Zero-dependency demo, append-only auditability, easy inspection; replaceable by PostgreSQL/TimescaleDB. |
| Threat intelligence | VirusTotal, AbuseIPDB, OTX adapter boundary | Covers IP/domain/hash intelligence while providing offline fallback for reliable demos. |
| ML | scikit-learn Isolation Forest + Random Forest, joblib | Directly satisfies anomaly and supervised detection requirements with reproducible artifacts. |
| Orchestration | Policy-based Python SOAR engine | Explicit thresholds, analyst-in-the-loop routing, cases, audit trail, and safe simulated actions. |
| Dashboard | Streamlit + Plotly | Fast operational dashboard with drill-down and interactive visualizations. |
| Testing | pytest | Focused unit tests for normalization, caching, and detection. |
| Configuration | YAML + environment variables | Centralized settings without committing secrets. |

## Production hardening path

Use Kafka/Redpanda for the queue, PostgreSQL/TimescaleDB for events and cases, Redis for the TI cache, OpenTelemetry for tracing, OIDC/RBAC for access control, Vault/KMS for secrets, and containerized deployment behind a TLS ingress.
