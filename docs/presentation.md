# SentinelForge — AI Security Automation Platform

## Slide 1 — The problem
Security telemetry is fragmented across authentication, network, web, DNS, endpoint, and VPN sources. Analysts need a common event model, explainable prioritization, and safe response automation.

**Capstone:** integrate intelligence, machine learning, SOAR, and operations into one reproducible platform.

## Slide 2 — The solution
SentinelForge connects five modules:

- Data ingestion and normalization
- Threat intelligence enrichment
- Hybrid ML threat detection
- Confidence-based SOAR orchestration
- Real-time SOC dashboard and case view

The platform is offline-first for reliable assessment execution and supports optional live providers.

## Slide 3 — Technical architecture
Raw sources flow through schema validation into normalized events. IPs, domains, and hashes are enriched through a TTL cache and optional providers. Isolation Forest and a supervised classifier produce explainable confidence. Policy thresholds route alerts to automated playbooks, analyst review, or closure. Every decision is written to audit evidence.

## Slide 4 — Evidence-driven demo
Run `python platform.py --mode full --input data/sample_logs.jsonl`.

Show normalized JSONL, TI bands, anomaly and supervised scores, generated cases, then launch `streamlit run dashboard.py` to show KPIs, timeline, threat origin, and analyst queue.

## Slide 5 — Engineering challenges overcome

- Designed provider adapters that degrade safely when APIs or credentials are unavailable.
- Combined behavioral anomaly and supervised probabilities instead of trusting one signal.
- Added analyst approval boundaries before any response action.
- Made model training and sample telemetry deterministic and reproducible.

## Slide 6 — Future improvements
Kafka/Redpanda, PostgreSQL/TimescaleDB, Redis, OIDC/RBAC, OpenTelemetry, signed model artifacts, drift monitoring, real EDR isolation with approval gates, and deployment behind a TLS ingress.

## Slide 7 — Thank you
**Adeen Shahzad**  
AI & Security Automation Engineer  
[LinkedIn](https://www.linkedin.com/in/adeen-shahzad-) · [GitHub](https://github.com/anon-443)
