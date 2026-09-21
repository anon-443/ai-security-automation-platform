# SentinelForge — 10-Minute Demo Script

## Before recording

Open a terminal in the repository and prepare a clean run:

```bash
rm -rf runtime models
mkdir -p runtime models
python platform.py --mode full --input data/sample_logs.jsonl
```

Keep a second terminal ready for:

```bash
streamlit run dashboard.py
```

Record the screen and your voice. Keep the terminal font large enough to read. Do not show API keys or personal secrets.

## 0:00–1:00 — Architecture and objective

**Show:** `docs/architecture_diagram.png`.

**Say:**

> This is SentinelForge, an AI Security Automation Platform built for the THE ARZENS Week 10 capstone. It integrates five modules: data ingestion, threat-intelligence enrichment, machine-learning detection, SOAR orchestration, and a security operations dashboard. The design is offline-first for reproducibility, but the threat-intelligence layer also supports VirusTotal, AbuseIPDB, and AlienVault OTX through environment-based API keys. The pipeline produces auditable evidence at every stage.

Briefly point to the flow from sources, through normalization and enrichment, into ML, SOAR, cases, and the dashboard.

## 1:00–2:30 — Data ingestion and normalization

**Show:** terminal and run:

```bash
python ingest_logs.py --input data/sample_logs.jsonl
head -n 2 runtime/events.jsonl
```

**Say:**

> The first module accepts line-oriented JSON logs and can also process CSV records or simulated streaming events. Every input is normalized to a common schema containing timestamp, source, event type, username, source and destination IP, action, status, traffic volume, duration, geographic context, and optional domain or hash indicators.
>
> Each event receives a stable event ID and ingestion timestamp. This makes events traceable across intelligence, detection, and response. The normalized output is written to an append-only JSONL evidence store, which acts as the local processing queue in this demonstration.

Point out one `event_id`, `src_ip`, `action`, and `status` field in the output.

## 2:30–4:00 — Threat-intelligence enrichment

**Show:** run:

```bash
python ti_enricher.py
python - <<'PY'
import json
from pathlib import Path
rows = [json.loads(x) for x in Path('runtime/enriched_events.jsonl').read_text().splitlines()]
for row in rows[:3]:
    print(row['src_ip'], row['ti_band'], row['ti_score'], row['threat_intelligence'])
PY
```

**Say:**

> The enrichment layer extracts IP addresses, domains, and hashes from normalized events. It checks a TTL cache before making a provider request. In a live environment, credentials can enable VirusTotal, AbuseIPDB, or AlienVault OTX. For this recorded demo, the offline adapter produces deterministic intelligence so the result is reproducible and no secret is exposed.
>
> The output is normalized into a risk score, risk band, malicious-vote count, provider source, and last-seen timestamp. If an external provider fails, the cache or offline fallback prevents the entire detection pipeline from stopping.

Point out the `critical` or `high` TI band for a suspicious IP and the cache file at `runtime/ti_cache.json`.

## 4:00–6:00 — Machine-learning detection

**Show:** run:

```bash
python ml_detector.py
python - <<'PY'
import json
from pathlib import Path
rows = [json.loads(x) for x in Path('runtime/alerts.jsonl').read_text().splitlines()]
for row in sorted(rows, key=lambda x: x['confidence'], reverse=True)[:4]:
    print(row['action'], row['prediction'], row['confidence'], row['anomaly_score'], row['supervised_score'], row['alert_severity'])
PY
```

**Say:**

> The detection module uses two complementary models. Isolation Forest identifies behavior that is unusual compared with the baseline feature distribution. The supervised Random Forest estimates the probability that an event belongs to the threat class. Features include bytes, duration, failed-authentication behavior, suspicious-action indicators, and the threat-intelligence score.
>
> The platform combines the anomaly and supervised scores into a confidence value. This is more defensible than using one model alone. For example, a port scan or encoded PowerShell event with a suspicious indicator receives a high confidence and high severity classification.
>
> The model artifacts are saved with joblib and can be replaced by a validated Week 05 model without changing the pipeline contract.

Explain that `prediction`, `confidence`, `anomaly_score`, `supervised_score`, and `alert_severity` are the evidence fields.

## 6:00–7:30 — SOAR orchestration and analyst-in-the-loop

**Show:** run:

```bash
python soar_engine.py
cat runtime/cases.jsonl
cat runtime/audit.jsonl
```

**Say:**

> The SOAR engine applies explicit confidence policies. High-confidence alerts create an automated case and an isolation recommendation. Medium-confidence alerts are routed to an analyst review queue. Low-confidence events are closed with a no-action audit record.
>
> The demo deliberately simulates response actions rather than isolating a real host. This is a safety control. In production, the same playbook boundary could call an EDR, ticketing system, email, or Slack after authentication and authorization checks.
>
> Every decision receives a case ID and an audit record containing the actor, decision, action, and result.

Point out `case_id`, `status`, `approval_required`, and `result: simulated_success`.

## 7:30–9:30 — Dashboard and interactive drill-down

**Show:** open the Streamlit URL and display the dashboard.

Walk through these in order:

1. KPI cards: events, alerts, high-confidence alerts, analyst queue, TI indicators.
2. Alert timeline: explain confidence over time and severity colors.
3. Detection mix: explain severity distribution.
4. Threat origin chart: explain country aggregation from normalized events.
5. SOAR playbook status: show automated versus analyst-review routing.
6. Alert drill-down table: select the highest-confidence alert.
7. Evidence expander: show the full raw event, TI result, ML features, and response fields.

**Say:**

> The dashboard is an operational view over the same evidence produced by the pipeline. It is not a static mockup: the charts and tables are loaded from normalized events, enriched records, alerts, cases, and audit results generated by the current run. The drill-down preserves the full chain from raw event to intelligence, model decision, and playbook outcome.

## 9:30–10:00 — Quality, security, and close

**Show:** the repository README and tests briefly.

Run or show the test result:

```bash
pytest -q
```

**Say:**

> The platform includes unit tests for schema normalization, threat-intelligence caching, and ML confidence generation. Configuration is centralized, secrets are environment-only, provider failures degrade safely, and destructive response actions are disabled in demo mode. For production scale, I would replace JSONL with Kafka and PostgreSQL or TimescaleDB, use Redis for shared caching, add OIDC/RBAC and TLS, and introduce signed model artifacts and drift monitoring.
>
> This completes the SentinelForge end-to-end AI Security Automation Platform demonstration. Thank you.

## Recording tips

- Keep the demo under 10 minutes; rehearse once with a timer.
- Do not spend too long typing. Prepare commands in a text editor and paste them visibly.
- Keep the voice explanation focused on design decisions, not every line of code.
- Show real output from the current run rather than only describing planned features.
- If a live API is unavailable, explicitly say that the offline fallback is being demonstrated; this is an intentional reliability feature.
