# SecurityDash 🛡️

A **real-time security monitoring dashboard** built as a DevSecOps internship project.
Tracks login attempts, detects suspicious IPs, runs vulnerability scans, and visualises
everything live in Grafana — all running in Docker.

---

## Architecture

```
Internet / sim.py
      │
      ▼
 FastAPI (port 8000)          ← API layer + brute-force detection + rate limiting
      │              │
      ▼              ▼
 PostgreSQL      Prometheus (port 9090)    ← scrapes /metrics every 15s
(persistent       │
 event log)       ▼
             Grafana (port 3001)           ← live dashboard + alerts
```

**Stack:** FastAPI · PostgreSQL · Prometheus · Grafana · OWASP ZAP · Docker Compose · slowapi

---

## Features

| Feature | Details |
|---|---|
| **Brute-force detection** | IPs with 5+ failed logins are flagged and blocked in PostgreSQL |
| **Rate limiting** | `/login` capped at 10 req/s and 30 req/min per IP — returns HTTP 429 |
| **API key auth** | All `/report/*` endpoints require `X-Api-Key` header |
| **12 Prometheus metrics** | Counters, Gauges, Histograms for logins, response time, CPU/memory, ZAP results |
| **7 alert rules** | Brute force, slow API, high CPU, ZAP HIGH vulns, service down |
| **ZAP integration** | `/ingest-zap` parses OWASP ZAP JSON reports and saves findings to DB |
| **Grafana dashboard** | 7 panels — login trends, suspicious IPs, response time p95, system resources, vuln counts |
| **Reporting API** | `/report/summary`, `/report/logins`, `/report/alerts`, `/report/suspicious-ips` |

---

## Quick Start

### Prerequisites
- Docker + Docker Compose installed
- Ports 8000, 9090, 3001 open

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/SecurityDash.git
cd SecurityDash
```

### 2. Set up environment variables
```bash
cp .env.example .env
```

Edit `.env` with your values:
```env
POSTGRES_PASSWORD=your-strong-password
API_KEY=your-secret-api-key
GRAFANA_ADMIN_PASSWORD=your-grafana-password
```

Generate a secure API key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Start all services
```bash
docker-compose up --build -d
```

### 4. Access the services

| Service | URL | Credentials |
|---|---|---|
| FastAPI docs | http://localhost:8000/docs | None |
| Prometheus | http://localhost:9090 | None |
| Grafana | http://localhost:3001 | admin / (from .env) |

### 5. Start the traffic simulator
```bash
pip install requests
python sim/sim.py
```

This sends randomised login traffic so Grafana panels populate immediately.

---

## API Reference

### Public Endpoints (no auth)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check + CPU/memory |
| POST | `/login` | Simulated login (rate limited: 10/s, 30/min) |
| POST | `/ingest-zap` | Ingest OWASP ZAP scan results |
| GET | `/metrics` | Prometheus scrape endpoint |

### Protected Endpoints (require `X-Api-Key` header)

| Method | Path | Description |
|---|---|---|
| GET | `/report/summary` | Full security summary |
| GET | `/report/logins` | Recent login events |
| GET | `/report/alerts` | Alert history |
| GET | `/report/suspicious-ips` | Flagged IP list |
| GET | `/report/scans` | ZAP scan history |
| PATCH | `/report/alerts/{id}/resolve` | Resolve an alert |

**Example:**
```bash
curl -H "X-Api-Key: your-secret-key" http://localhost:8000/report/summary
```

---

## Rate Limiting

`/login` is protected by [slowapi](https://github.com/laurentS/slowapi):

- **10 requests/second** per IP — DDoS protection
- **30 requests/minute** per IP — brute-force protection
- Exceeding either limit returns **HTTP 429 Too Many Requests**
- Every blocked request increments the `rate_limit_exceeded_total` Prometheus counter

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://...` | Full PostgreSQL connection string |
| `POSTGRES_USER` | `secuser` | PostgreSQL username |
| `POSTGRES_PASSWORD` | `secpass` | PostgreSQL password (**change this**) |
| `POSTGRES_DB` | `securitydash` | Database name |
| `API_KEY` | `changeme-...` | Key for `/report/*` endpoints (**change this**) |
| `GRAFANA_ADMIN_USER` | `admin` | Grafana admin username |
| `GRAFANA_ADMIN_PASSWORD` | `securitydash` | Grafana admin password (**change this**) |

---

## Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `failed_login_attempts_total` | Counter | Failed logins by IP + username |
| `successful_login_attempts_total` | Counter | Successful logins by IP |
| `rate_limit_exceeded_total` | Counter | Requests blocked by rate limiter |
| `api_response_time_seconds` | Histogram | Per-route response latency |
| `active_users_total` | Gauge | Currently active users |
| `suspicious_ip_count_total` | Gauge | IPs with 5+ failed logins |
| `system_cpu_usage_percent` | Gauge | Host CPU % |
| `system_memory_usage_percent` | Gauge | Host memory % |
| `zap_vulnerabilities_high_total` | Gauge | ZAP HIGH findings |

---

## Project Structure

```
SecurityDash/
├── app/
│   └── main.py                  # FastAPI app — routes, metrics, DB logic
├── sim/
│   └── sim.py                   # Traffic simulator
├── prometheus/
│   ├── prometheus.yml           # Scrape config
│   └── alert_rules.yml          # 7 alert rules
├── grafana/
│   └── provisioning/            # Auto-loaded dashboard + datasource
├── zap_scan.py                  # OWASP ZAP automation
├── docker-compose.yml           # All 4 services
├── Dockerfile                   # FastAPI container
├── requirements.txt
├── .env.example                 # Environment variable template
└── .gitignore
```

---

## Security Notes

- `.env` is in `.gitignore` — never commit real credentials
- `/report/*` routes require API key authentication
- Rate limiting blocks brute-force and DDoS attempts at HTTP level
- `X-Forwarded-For` is read for client IP (trust only from known proxies in production)
- Default passwords in `.env.example` must be changed before deployment

---

## License

MIT
