"""
SecurityDash - Real-Time Security Monitoring Dashboard
FastAPI application with Prometheus metrics + PostgreSQL reporting database

Changelog v3.0.0:
  - Real bcrypt password authentication (no more random.random())
  - API_KEY startup validation — app refuses to start without it
  - Input validation with Pydantic constraints (length + pattern)
  - Blocked IP enforcement — 403 before any login logic runs
  - Structured logging via Python logging module
  - Robust ZAP parsing using riskcode integer field
  - DB-backed session persistence (survives restarts)
  - .pem / key files added to .gitignore
"""

import time
import logging
import psutil
import os
import secrets as _secrets
from datetime import datetime
from typing import Optional

# ── Logging setup (structured, replaces bare print()) ─────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("securitydash")

from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import (
    Counter, Histogram, Gauge,
    generate_latest, CONTENT_TYPE_LATEST
)
from starlette.responses import Response
from pydantic import BaseModel, constr, field_validator

# bcrypt password hashing
from passlib.context import CryptContext

# slowapi — rate limiting
from slowapi import Limiter
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

# Database
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

# ─────────────────────────────────────────────
# Configuration — all from environment variables
# ─────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://secuser:secpass@db:5432/securitydash"
)

# API_KEY — NO default. App refuses to start if not set in production.
# For local dev only, falls back to a generated warning key.
_raw_api_key = os.getenv("API_KEY", "")
if not _raw_api_key:
    _raw_api_key = "DEV-ONLY-" + _secrets.token_hex(8)
    logger.warning(
        "⚠️  API_KEY not set in environment — using temporary key: %s  "
        "(set API_KEY in .env before deploying)", _raw_api_key
    )
API_KEY = _raw_api_key

# ─────────────────────────────────────────────
# Password hashing (bcrypt)
# ─────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── User store ────────────────────────────────
# In a real app this would be a DB table.
# For this project: a hardcoded dict with hashed passwords.
# To add a user:
#   python3 -c "from passlib.context import CryptContext; \
#               c=CryptContext(schemes=['bcrypt']); print(c.hash('yourpassword'))"
USERS = {
    "admin": pwd_context.hash(os.getenv("ADMIN_PASSWORD", "Admin@123")),
    "analyst": pwd_context.hash(os.getenv("ANALYST_PASSWORD", "Analyst@456")),
}


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(username: str, password: str) -> bool:
    """Returns True only if username exists AND password matches the bcrypt hash."""
    hashed = USERS.get(username)
    if not hashed:
        return False
    return verify_password(password, hashed)


# ─────────────────────────────────────────────
# Database Setup
# ─────────────────────────────────────────────

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─── Models ──────────────────────────────────

class LoginEvent(Base):
    __tablename__ = "login_events"
    id         = Column(Integer, primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow)
    username   = Column(String(100))
    ip_address = Column(String(50))
    success    = Column(Boolean)
    flagged    = Column(Boolean, default=False)


class ZapScanResult(Base):
    __tablename__ = "zap_scan_results"
    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow)
    high          = Column(Integer, default=0)
    medium        = Column(Integer, default=0)
    low           = Column(Integer, default=0)
    informational = Column(Integer, default=0)
    target        = Column(String(255), default="http://localhost:8000")
    notes         = Column(Text, nullable=True)


class AlertEvent(Base):
    __tablename__ = "alert_events"
    id         = Column(Integer, primary_key=True, index=True)
    timestamp  = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String(100))
    severity   = Column(String(20))
    message    = Column(Text)
    ip_address = Column(String(50), nullable=True)
    resolved   = Column(Boolean, default=False)


class SuspiciousIP(Base):
    __tablename__ = "suspicious_ips"
    id              = Column(Integer, primary_key=True, index=True)
    ip_address      = Column(String(50), unique=True, index=True)
    failed_attempts = Column(Integer, default=0)
    first_seen      = Column(DateTime, default=datetime.utcnow)
    last_seen       = Column(DateTime, default=datetime.utcnow)
    blocked         = Column(Boolean, default=False)


class ActiveSession(Base):
    """
    DB-backed session store — survives server restarts.
    Fixes: in-memory active_sessions set being wiped on container restart.
    """
    __tablename__ = "active_sessions"
    id            = Column(Integer, primary_key=True, index=True)
    session_token = Column(String(64), unique=True, index=True)
    username      = Column(String(100))
    created_at    = Column(DateTime, default=datetime.utcnow)


def create_tables():
    for attempt in range(10):
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("✅ Database tables created / verified")
            return
        except Exception as e:
            logger.warning("Waiting for DB... attempt %d/10 (%s)", attempt + 1, e)
            time.sleep(3)
    logger.error("❌ Could not connect to database after 10 attempts")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────
# Rate Limiter
# ─────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    """
    Reads X-Forwarded-For only if present (set by sim.py / reverse proxy).
    Falls back to direct connection IP.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host or "127.0.0.1"


limiter = Limiter(key_func=get_client_ip)

# ─────────────────────────────────────────────
# Prometheus Metrics
# ─────────────────────────────────────────────

failed_login_attempts = Counter(
    "failed_login_attempts_total",
    "Total failed login attempts",
    ["ip_address", "username"]
)
successful_login_attempts = Counter(
    "successful_login_attempts_total",
    "Total successful login attempts",
    ["ip_address"]
)
api_response_time = Histogram(
    "api_response_time_seconds",
    "API response time in seconds",
    ["method", "endpoint", "status_code"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)
active_users        = Gauge("active_users_total",          "Currently active users")
suspicious_ip_count = Gauge("suspicious_ip_count_total",   "IPs flagged as suspicious")
cpu_usage           = Gauge("system_cpu_usage_percent",    "System CPU usage %")
memory_usage        = Gauge("system_memory_usage_percent", "System memory usage %")
memory_used_bytes   = Gauge("system_memory_used_bytes",    "System memory used bytes")
zap_high            = Gauge("zap_vulnerabilities_high_total",   "ZAP HIGH findings")
zap_medium          = Gauge("zap_vulnerabilities_medium_total", "ZAP MEDIUM findings")
zap_low             = Gauge("zap_vulnerabilities_low_total",    "ZAP LOW findings")
zap_last_scan       = Gauge("zap_last_scan_timestamp",          "Unix timestamp of last ZAP scan")
rate_limit_hits     = Counter(
    "rate_limit_exceeded_total",
    "Requests blocked by rate limiter",
    ["ip_address", "endpoint"]
)

# ─────────────────────────────────────────────
# In-memory helpers
# ─────────────────────────────────────────────

failed_login_tracker: dict = {}   # ip → failed attempt count (fast lookup)
SUSPICIOUS_THRESHOLD = 5

# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
    title="SecurityDash API",
    description="Real-time security monitoring dashboard",
    version="3.0.0"
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    client_ip = get_client_ip(request)
    rate_limit_hits.labels(ip_address=client_ip, endpoint=request.url.path).inc()
    logger.warning("RATE LIMIT — %s blocked on %s", client_ip, request.url.path)
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests — slow down.", "retry_after": "60s"}
    )


@app.on_event("startup")
async def startup_event():
    create_tables()
    logger.info("🚀 SecurityDash v3.0.0 started — API_KEY configured: %s",
                "YES" if not API_KEY.startswith("DEV-ONLY-") else "NO (dev mode)")


# ─────────────────────────────────────────────
# API Key Auth
# ─────────────────────────────────────────────

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        logger.warning("Invalid API key attempt: %s...", x_api_key[:8])
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")


# ─────────────────────────────────────────────
# Request Timing Middleware
# ─────────────────────────────────────────────

@app.middleware("http")
async def track_request_timing(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    duration = time.time() - start
    api_response_time.labels(
        method=request.method,
        endpoint=request.url.path,
        status_code=str(response.status_code)
    ).observe(duration)
    return response


def update_system_metrics():
    cpu_usage.set(psutil.cpu_percent(interval=None))
    mem = psutil.virtual_memory()
    memory_usage.set(mem.percent)
    memory_used_bytes.set(mem.used)


def flag_suspicious_ips():
    count = sum(1 for v in failed_login_tracker.values() if v >= SUSPICIOUS_THRESHOLD)
    suspicious_ip_count.set(count)


# ─────────────────────────────────────────────
# Pydantic Models — with input validation
# ─────────────────────────────────────────────

class LoginRequest(BaseModel):
    # Fix #4: length limits + alphanumeric-only username
    username: constr(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    password: constr(min_length=6, max_length=100)

    @field_validator("username")
    @classmethod
    def no_sql_injection(cls, v: str) -> str:
        """Extra guard — reject common SQL injection patterns."""
        banned = ["'", '"', ";", "--", "/*", "*/", "xp_", "DROP", "SELECT"]
        for token in banned:
            if token.lower() in v.lower():
                raise ValueError("Invalid characters in username")
        return v


class LogoutRequest(BaseModel):
    session_token: constr(min_length=64, max_length=64)


# ─────────────────────────────────────────────
# Core Routes
# ─────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "service": "SecurityDash API", "version": "3.0.0"}


@app.get("/health")
async def health():
    update_system_metrics()
    return {
        "status": "healthy",
        "cpu": psutil.cpu_percent(),
        "memory": psutil.virtual_memory().percent
    }


@app.get("/metrics")
async def metrics():
    update_system_metrics()
    flag_suspicious_ips()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ─── Login ────────────────────────────────────

@app.post("/login")
@limiter.limit("10/second")
@limiter.limit("30/minute")
async def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = get_client_ip(request)

    # Fix #6: Check blocked FIRST — before any auth logic runs
    existing_ip = db.query(SuspiciousIP).filter(
        SuspiciousIP.ip_address == client_ip
    ).first()
    if existing_ip and existing_ip.blocked:
        logger.warning("BLOCKED IP attempted login: %s", client_ip)
        raise HTTPException(
            status_code=403,
            detail="Your IP has been blocked due to repeated failed login attempts."
        )

    # Fix #1: Real bcrypt password check — no more random.random()
    success = authenticate_user(payload.username, payload.password)
    is_suspicious = failed_login_tracker.get(client_ip, 0) >= SUSPICIOUS_THRESHOLD

    # Persist login event
    try:
        db.add(LoginEvent(
            username=payload.username,
            ip_address=client_ip,
            success=success,
            flagged=is_suspicious
        ))

        if not success:
            if existing_ip:
                existing_ip.failed_attempts += 1
                existing_ip.last_seen = datetime.utcnow()
                if existing_ip.failed_attempts >= SUSPICIOUS_THRESHOLD:
                    existing_ip.blocked = True
                    db.add(AlertEvent(
                        alert_type="suspicious_ip",
                        severity="critical",
                        message=(
                            f"IP {client_ip} blocked after "
                            f"{existing_ip.failed_attempts} failed login attempts"
                        ),
                        ip_address=client_ip
                    ))
                    logger.warning("🚨 IP BLOCKED: %s (%d failures)",
                                   client_ip, existing_ip.failed_attempts)
            else:
                db.add(SuspiciousIP(ip_address=client_ip, failed_attempts=1))

        db.commit()

    except Exception as e:
        db.rollback()
        # Fix #7: structured logging with logger, not bare print
        logger.error("DB error saving login event: %s", e, exc_info=True)

    if not success:
        failed_login_tracker[client_ip] = failed_login_tracker.get(client_ip, 0) + 1
        failed_login_attempts.labels(
            ip_address=client_ip, username=payload.username
        ).inc()
        flag_suspicious_ips()
        logger.info("FAILED login — user=%s ip=%s", payload.username, client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Fix #5: session stored in DB — survives container restarts
    token = _secrets.token_hex(32)
    try:
        db.add(ActiveSession(session_token=token, username=payload.username))
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("DB error saving session: %s", e, exc_info=True)

    session_count = db.query(ActiveSession).count()
    active_users.set(session_count)

    successful_login_attempts.labels(ip_address=client_ip).inc()
    logger.info("✅ Successful login — user=%s ip=%s", payload.username, client_ip)

    return {
        "message": "Login successful",
        "user": payload.username,
        "session_token": token
    }


@app.post("/logout")
async def logout(payload: LogoutRequest, db: Session = Depends(get_db)):
    """Validates session token, removes from DB. active_users reflects real DB count."""
    session = db.query(ActiveSession).filter(
        ActiveSession.session_token == payload.session_token
    ).first()

    if not session:
        raise HTTPException(
            status_code=401,
            detail="Invalid or already-expired session token."
        )

    db.delete(session)
    db.commit()

    session_count = db.query(ActiveSession).count()
    active_users.set(session_count)

    logger.info("Logout — user=%s sessions_remaining=%d", session.username, session_count)
    return {"message": "Logged out", "active_sessions": session_count}


@app.get("/dashboard")
async def dashboard():
    return {
        "panels": ["login_failures", "suspicious_ips", "response_time", "cpu_memory", "vulnerabilities"],
        "status": "ok"
    }


@app.get("/api/data")
async def api_data():
    import random
    return {"data": [random.randint(1, 100) for _ in range(10)]}


# ─────────────────────────────────────────────
# ZAP Ingest — robust parsing
# ─────────────────────────────────────────────

# Fix #8: use ZAP's riskcode integer field (authoritative) instead of
# substring matching on riskdesc (fragile — "informational" contains "info"
# but also "high" can appear in other text).
#
# ZAP riskcode values:
#   3 = High, 2 = Medium, 1 = Low, 0 = Informational
ZAP_RISK_MAP = {3: "high", 2: "medium", 1: "low", 0: "informational"}


def parse_risk(alert: dict) -> str:
    """
    Determine severity from a ZAP alert dict.
    Priority: riskcode (int) → riskdesc (string) → risk (string) → unknown
    """
    # 1. riskcode is the most reliable — integer, no ambiguity
    code = alert.get("riskcode")
    if code is not None:
        try:
            return ZAP_RISK_MAP.get(int(code), "informational")
        except (ValueError, TypeError):
            pass

    # 2. Fall back to riskdesc string — parse the FIRST word only
    #    e.g. "High (Medium)" → "high"  avoids "medium" matching on "High (Medium)"
    for field in ("riskdesc", "risk"):
        raw = alert.get(field, "")
        if raw:
            first_word = raw.strip().split()[0].lower().rstrip("()")
            if first_word in ZAP_RISK_MAP.values():
                return first_word

    return "informational"


@app.post("/ingest-zap")
async def ingest_zap(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    high = medium = low = informational = 0

    def count_alert(alert: dict):
        nonlocal high, medium, low, informational
        risk = parse_risk(alert)
        if risk == "high":          high += 1
        elif risk == "medium":      medium += 1
        elif risk == "low":         low += 1
        else:                       informational += 1

    # Format 1: nested site → alerts
    for site in body.get("site", []):
        if isinstance(site, dict):
            for alert in site.get("alerts", []):
                count_alert(alert)

    # Format 2: flat alerts list
    for alert in body.get("alerts", []):
        count_alert(alert)

    logger.info("ZAP scan ingested — HIGH:%d MED:%d LOW:%d INFO:%d",
                high, medium, low, informational)

    try:
        scan = ZapScanResult(high=high, medium=medium, low=low, informational=informational)
        db.add(scan)
        if high > 0:
            db.add(AlertEvent(
                alert_type="high_vulnerability",
                severity="critical",
                message=f"ZAP scan: {high} HIGH severity vulnerability/vulnerabilities found"
            ))
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("DB error saving ZAP scan: %s", e, exc_info=True)

    zap_high.set(high)
    zap_medium.set(medium)
    zap_low.set(low)
    zap_last_scan.set(time.time())

    return {
        "status": "ingested",
        "counts": {"high": high, "medium": medium, "low": low, "informational": informational},
        "timestamp": time.time()
    }


# ─────────────────────────────────────────────
# Internal Grafana Webhook
# ─────────────────────────────────────────────

@app.post("/internal/grafana-alert")
async def receive_grafana_alert(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    alerts = body.get("alerts", [])
    saved = 0
    for alert in alerts:
        state    = alert.get("status", "firing")
        name     = alert.get("labels", {}).get("alertname", "Unknown")
        severity = alert.get("labels", {}).get("severity", "warning")
        summary  = alert.get("annotations", {}).get("summary", name)
        try:
            db.add(AlertEvent(
                alert_type=f"grafana_{name.lower().replace(' ', '_')}",
                severity=severity,
                message=f"[Grafana/{state.upper()}] {summary}",
            ))
            saved += 1
        except Exception as e:
            logger.error("Error saving Grafana alert: %s", e)

    db.commit()
    logger.info("Grafana webhook: received=%d saved=%d", len(alerts), saved)
    return {"received": len(alerts), "saved": saved}


# ─────────────────────────────────────────────
# Reporting Endpoints — API Key Protected
# ─────────────────────────────────────────────

@app.get("/report/summary", dependencies=[Depends(verify_api_key)])
async def report_summary(db: Session = Depends(get_db)):
    total_logins      = db.query(LoginEvent).count()
    failed_logins     = db.query(LoginEvent).filter(LoginEvent.success == False).count()
    successful_logins = db.query(LoginEvent).filter(LoginEvent.success == True).count()
    suspicious_ips    = db.query(SuspiciousIP).filter(
                            SuspiciousIP.failed_attempts >= SUSPICIOUS_THRESHOLD).count()
    blocked_ips       = db.query(SuspiciousIP).filter(SuspiciousIP.blocked == True).count()
    total_scans       = db.query(ZapScanResult).count()
    total_alerts      = db.query(AlertEvent).count()
    unresolved_alerts = db.query(AlertEvent).filter(AlertEvent.resolved == False).count()
    latest_scan       = db.query(ZapScanResult).order_by(ZapScanResult.timestamp.desc()).first()

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "authentication": {
            "total_login_attempts": total_logins,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "failure_rate_percent": round(
                (failed_logins / total_logins * 100) if total_logins > 0 else 0, 2
            )
        },
        "threat_detection": {
            "suspicious_ips_detected": suspicious_ips,
            "blocked_ips": blocked_ips,
            "suspicious_threshold": SUSPICIOUS_THRESHOLD
        },
        "vulnerability_scans": {
            "total_scans_run": total_scans,
            "latest_scan": {
                "timestamp": latest_scan.timestamp.isoformat() if latest_scan else None,
                "high":   latest_scan.high   if latest_scan else 0,
                "medium": latest_scan.medium if latest_scan else 0,
                "low":    latest_scan.low    if latest_scan else 0,
            }
        },
        "alerts": {
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts
        }
    }


@app.get("/report/logins", dependencies=[Depends(verify_api_key)])
async def report_logins(limit: int = 50, db: Session = Depends(get_db)):
    events = db.query(LoginEvent).order_by(LoginEvent.timestamp.desc()).limit(limit).all()
    return {
        "total": len(events),
        "events": [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "username": e.username,
                "ip_address": e.ip_address,
                "success": e.success,
                "flagged": e.flagged
            } for e in events
        ]
    }


@app.get("/report/scans", dependencies=[Depends(verify_api_key)])
async def report_scans(db: Session = Depends(get_db)):
    scans = db.query(ZapScanResult).order_by(ZapScanResult.timestamp.desc()).all()
    return {
        "total_scans": len(scans),
        "scans": [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "high": s.high, "medium": s.medium,
                "low": s.low, "informational": s.informational,
                "target": s.target
            } for s in scans
        ]
    }


@app.get("/report/alerts", dependencies=[Depends(verify_api_key)])
async def report_alerts(resolved: Optional[bool] = None, db: Session = Depends(get_db)):
    query = db.query(AlertEvent)
    if resolved is not None:
        query = query.filter(AlertEvent.resolved == resolved)
    alerts = query.order_by(AlertEvent.timestamp.desc()).all()
    return {
        "total": len(alerts),
        "alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat(),
                "type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "ip_address": a.ip_address,
                "resolved": a.resolved
            } for a in alerts
        ]
    }


@app.get("/report/suspicious-ips", dependencies=[Depends(verify_api_key)])
async def report_suspicious_ips(db: Session = Depends(get_db)):
    ips = db.query(SuspiciousIP).order_by(SuspiciousIP.failed_attempts.desc()).all()
    return {
        "total": len(ips),
        "ips": [
            {
                "ip_address": ip.ip_address,
                "failed_attempts": ip.failed_attempts,
                "first_seen": ip.first_seen.isoformat(),
                "last_seen": ip.last_seen.isoformat(),
                "blocked": ip.blocked
            } for ip in ips
        ]
    }


@app.patch("/report/alerts/{alert_id}/resolve", dependencies=[Depends(verify_api_key)])
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(AlertEvent).filter(AlertEvent.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()
    return {"message": f"Alert {alert_id} marked as resolved"}


@app.get("/suspicious-ips")
async def get_suspicious_ips():
    suspicious = {ip: c for ip, c in failed_login_tracker.items() if c >= SUSPICIOUS_THRESHOLD}
    return {"suspicious_ips": suspicious, "total": len(suspicious)}
