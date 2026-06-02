# SecurityDash — Real-Time Security Monitoring Dashboard

A DevSecOps internship project that monitors a FastAPI web application for security threats and vulnerabilities in real time, visualised via Grafana.

**Stack:** FastAPI · Prometheus · Grafana · OWASP ZAP · Python · psutil

---

## Architecture

```
sim.py  ──►  FastAPI (/login, /dashboard, /api/data)
                │
                │  /metrics (prometheus_client)
                ▼
           Prometheus  ──►  Grafana (5 panels, live alerts)
                │
           OWASP ZAP  ──►  POST /ingest-zap  ──►  Prometheus gauges
```

---

## Project Structure

```
SecurityDash/
├── app/
│   └── main.py              # FastAPI app + all Prometheus metrics
├── sim/
│   └── sim.py               # Traffic simulator
├── zap/
│   ├── zap_scan.py          # ZAP automation script
│   └── sample_zap_report.json
├── prometheus/
│   ├── prometheus.yml       # Scrape config
│   └── alert_rules.yml      # Alert rules (7 alerts)
├── grafana/
│   ├── dashboard.json       # Full 5-panel dashboard (import this)
│   └── provisioning/        # Auto-provisioning config for Docker
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Quick Start (Local — no Docker)

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the FastAPI app

```bash
uvicorn app.main:app --reload --port 8000
```

Visit: http://localhost:8000/docs (Swagger UI)
Metrics: http://localhost:8000/metrics

### 3. Install & start Prometheus

Download from https://prometheus.io/download/

```bash
# Copy prometheus.yml into the Prometheus folder, then:
./prometheus --config.file=prometheus/prometheus.yml
```

Prometheus UI: http://localhost:9090

### 4. Install & start Grafana

Download from https://grafana.com/grafana/download

```bash
# macOS
brew install grafana && brew services start grafana

# Linux (systemd)
sudo systemctl start grafana-server
```

Grafana: http://localhost:3000 (admin / admin)

**Import the dashboard:**
- Go to Dashboards → Import
- Upload `grafana/dashboard.json`
- Select "Prometheus" as the data source

### 5. Start the traffic simulator

```bash
python sim/sim.py --rate 2
```

Watch the Grafana panels update live!

### 6. Run a ZAP scan

Option A — with ZAP installed:
```bash
# Start ZAP with API enabled, then:
python zap/zap_scan.py --report
```

Option B — use the sample report (no ZAP needed):
```bash
curl -X POST http://localhost:8000/ingest-zap \
  -H "Content-Type: application/json" \
  -d @zap/sample_zap_report.json
```

---

## Quick Start (Docker Compose)

```bash
docker-compose up -d
```

| Service     | URL                   |
|-------------|-----------------------|
| FastAPI     | http://localhost:8000 |
| Prometheus  | http://localhost:9090 |
| Grafana     | http://localhost:3000 |

Grafana credentials: `admin` / `securitydash`

---

## Prometheus Metrics Exposed

| Metric | Type | Description |
|--------|------|-------------|
| `failed_login_attempts_total` | Counter | Failed logins, labelled by IP + username |
| `successful_login_attempts_total` | Counter | Successful logins by IP |
| `api_response_time_seconds` | Histogram | Per-route response time |
| `active_users_total` | Gauge | Currently active users |
| `suspicious_ip_count_total` | Gauge | IPs with 5+ failed logins |
| `system_cpu_usage_percent` | Gauge | Host CPU % |
| `system_memory_usage_percent` | Gauge | Host memory % |
| `system_memory_used_bytes` | Gauge | Memory used (bytes) |
| `zap_vulnerabilities_high_total` | Gauge | ZAP HIGH severity findings |
| `zap_vulnerabilities_medium_total` | Gauge | ZAP MEDIUM severity findings |
| `zap_vulnerabilities_low_total` | Gauge | ZAP LOW severity findings |
| `zap_last_scan_timestamp` | Gauge | Unix timestamp of last ZAP scan |

---

## Grafana Dashboard Panels

1. **Login Attempts Over Time** — time series of failed vs successful logins
2. **Suspicious IPs** — stat panel, turns red when IPs exceed threshold
3. **Failed Logins (Last Hour)** — rolling count
4. **API Response Time p50/p95/p99** — histogram quantiles
5. **CPU & Memory Usage** — gauges + time series
6. **ZAP Vulnerability Counts** — stat + bar chart by severity
7. **Last ZAP Scan Timestamp** — when was the last scan

---

## Alert Rules

| Alert | Condition | Severity |
|-------|-----------|----------|
| HighFailedLoginRate | rate > 0.5/s for 1m | warning |
| SuspiciousIPsDetected | suspicious_ip_count > 0 | critical |
| SlowAPIResponse | p95 > 1s for 2m | warning |
| HighCPUUsage | CPU > 80% for 5m | warning |
| HighMemoryUsage | Memory > 85% for 5m | warning |
| HighSeverityVulnerabilities | ZAP HIGH > 0 | critical |
| SecurityDashDown | up == 0 for 1m | critical |

---

## PromQL Reference

```promql
# Failed login rate per minute
rate(failed_login_attempts_total[5m]) * 60

# API response time 95th percentile
histogram_quantile(0.95, rate(api_response_time_seconds_bucket[5m]))

# Total failed logins in last hour
increase(failed_login_attempts_total[1h])

# Failed logins per IP
sum by (ip_address) (increase(failed_login_attempts_total[1h]))
```

---

## Tech Stack

- **FastAPI** — Modern Python web framework with automatic OpenAPI docs
- **prometheus-client** — Python library to expose Prometheus metrics
- **Prometheus** — Time-series metrics database with PromQL query language
- **Grafana** — Visualization and alerting platform
- **OWASP ZAP** — Open-source web application security scanner
- **psutil** — Cross-platform system metrics (CPU, memory)

---

## What I Built

This project simulates a real-world DevSecOps monitoring setup where:
- A web app exposes structured metrics about security events
- A metrics server continuously collects and stores this data
- A dashboard provides real-time visibility into threats
- An automated scanner finds vulnerabilities and feeds them into the same dashboard

All components are wired together so a single Grafana view shows both operational metrics (response time, CPU) and security metrics (failed logins, vulnerabilities) simultaneously.
