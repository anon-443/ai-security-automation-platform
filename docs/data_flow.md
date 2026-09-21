# Data Flow

SentinelForge implements a staged security pipeline with explicit evidence files between modules. This makes the system easy to inspect during a live review while retaining a clean boundary for replacing JSONL with Kafka, PostgreSQL, or a SIEM connector.

1. **Sources → ingestion.** JSONL/CSV files, REST adapters, and the stream simulator produce raw records. The ingestion layer validates required fields, adds a stable event ID, timestamps the ingestion, and maps records into the common schema.
2. **Ingestion → normalized store.** Normalized events are appended to `runtime/events.jsonl`, acting as a durable local queue for the demo.
3. **Normalized events → TI enrichment.** IPs, domains, and hashes are extracted. The enrichment service checks a TTL cache first, then optionally calls VirusTotal or AbuseIPDB, and finally uses deterministic offline intelligence if APIs are unavailable. The result is a normalized risk score and band.
4. **Enriched events → ML detector.** Numeric features are generated from event behavior and TI results. Isolation Forest generates an anomaly score; a supervised Random Forest supplies a threat probability. The confidence policy combines both signals.
5. **Alerts → SOAR.** High-confidence alerts automatically create a case and a simulated isolation recommendation. Medium-confidence alerts enter the analyst queue. Low-confidence events are closed with an audit record.
6. **Evidence → dashboard.** Streamlit reads the event, alert, case, and audit stores to render KPIs, timeline charts, threat origin, playbook status, and evidence drill-downs.

All stages degrade safely: a failed TI provider does not stop detection, and simulated response actions never execute destructive controls.
