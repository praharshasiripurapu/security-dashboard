"""
SecurityDash - Real-Time Security Monitoring Dashboard
FastAPI application with Prometheus metrics + PostgreSQL reporting database
"""

import time
import random
import psutil
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import (
    Counter, Histogram, Gauge,
    generate_latest, CONTENT_TYPE_LATEST
)
from starlette.responses import Response
from pydantic import BaseModel

# Database imports
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os

# ─────────────────────────────────────────────
# Database Setup
# ─────────────────────────────────────────────

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://secuser:secpass@db:5432/securitydash"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─── Database Models ─────────────────────────

class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    username = Column(String(100))
    ip_address = Column(String(50))
    success = Column(Boolean)
    flagged = Column(Boolean, default=False)  # True if IP is suspicious


class ZapScanResult(Base):
    __tablename__ = "zap_scan_results"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)
    informational = Column(Integer, default=0)
    target = Column(String(255), default="http://localhost:8000")
    notes = Column(Text, nullable=True)


class AlertEvent(Base):
    __tablename__ = "alert_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_type = Column(String(100))   # e.g. "suspicious_ip", "high_vuln"
    severity = Column(String(20))      # critical / warning / info
    message = Column(Text)
    ip_address = Column(String(50), nullable=True)
    resolved = Column(Boolean, default=False)


class SuspiciousIP(Base):
    __tablename__ = "suspicious_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(50), unique=True, index=True)
    failed_attempts = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    blocked = Column(Boolean, default=False)


def create_tables():
    """Create all tables on startup."""
    for attempt in range(10):
        try:
            Base.metadata.create_all(bind=engine)
            print("[DB] Tables created successfully")
            return
        except Exception as e:
            print(f"[DB] Waiting for database... attempt {attempt+1}/10 ({e})")
            time.sleep(3)
    print("[DB] WARNING: Could not connect to database after 10 attempts")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────

app = FastAPI(
    title="SecurityDash API",
    description="Security monitoring dashboard backend with PostgreSQL reporting",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    create_tables()


# ─────────────────────────────────────────────
# Prometheus Metrics
# ─────────────────────────────────────────────

failed_login_attempts = Counter(
    "failed_login_attempts_total",
    "Total number of failed login attempts",
    ["ip_address", "username"]
)

successful_login_attempts = Counter(
    "successful_login_attempts_total",
    "Total number of successful login attempts",
    ["ip_address"]
)

api_response_time = Histogram(
    "api_response_time_seconds",
    "API response time in seconds",
    ["method", "endpoint", "status_code"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

active_users = Gauge("active_users_total", "Number of currently active users")
suspicious_ip_count = Gauge("suspicious_ip_count_total", "Number of IPs flagged as suspicious")
cpu_usage = Gauge("system_cpu_usage_percent", "System CPU usage percentage")
memory_usage = Gauge("system_memory_usage_percent", "System memory usage percentage")
memory_used_bytes = Gauge("system_memory_used_bytes", "System memory used in bytes")

zap_vulnerabilities_high = Gauge("zap_vulnerabilities_high_total", "HIGH severity vulnerabilities")
zap_vulnerabilities_medium = Gauge("zap_vulnerabilities_medium_total", "MEDIUM severity vulnerabilities")
zap_vulnerabilities_low = Gauge("zap_vulnerabilities_low_total", "LOW severity vulnerabilities")
zap_last_scan_timestamp = Gauge("zap_last_scan_timestamp", "Unix timestamp of last ZAP scan")

# ─────────────────────────────────────────────
# In-memory state
# ─────────────────────────────────────────────

failed_login_tracker: dict = {}
SUSPICIOUS_THRESHOLD = 5

# ─────────────────────────────────────────────
# Middleware
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
    suspicious = sum(1 for count in failed_login_tracker.values() if count >= SUSPICIOUS_THRESHOLD)
    suspicious_ip_count.set(suspicious)


# ─────────────────────────────────────────────
# Core Routes
# ─────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "service": "SecurityDash API", "version": "2.0.0"}


@app.get("/health")
async def health():
    update_system_metrics()
    return {"status": "healthy", "cpu": psutil.cpu_percent(), "memory": psutil.virtual_memory().percent}


@app.get("/metrics")
async def metrics():
    update_system_metrics()
    flag_suspicious_ips()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ─── Login ───────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/login")
async def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host or "127.0.0.1"
    success = random.random() > 0.4
    is_suspicious = failed_login_tracker.get(client_ip, 0) >= SUSPICIOUS_THRESHOLD

    # Save to DB
    try:
        event = LoginEvent(
            username=payload.username,
            ip_address=client_ip,
            success=success,
            flagged=is_suspicious
        )
        db.add(event)

        if not success:
            # Update suspicious IP table
            existing = db.query(SuspiciousIP).filter(SuspiciousIP.ip_address == client_ip).first()
            if existing:
                existing.failed_attempts += 1
                existing.last_seen = datetime.utcnow()
                if existing.failed_attempts >= SUSPICIOUS_THRESHOLD:
                    existing.blocked = True
                    # Log alert
                    alert = AlertEvent(
                        alert_type="suspicious_ip",
                        severity="critical",
                        message=f"IP {client_ip} has {existing.failed_attempts} failed login attempts",
                        ip_address=client_ip
                    )
                    db.add(alert)
            else:
                db.add(SuspiciousIP(ip_address=client_ip, failed_attempts=1))

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] Error saving login event: {e}")

    if not success:
        failed_login_tracker[client_ip] = failed_login_tracker.get(client_ip, 0) + 1
        failed_login_attempts.labels(ip_address=client_ip, username=payload.username).inc()
        flag_suspicious_ips()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    successful_login_attempts.labels(ip_address=client_ip).inc()
    active_users.inc()
    return {"message": "Login successful", "user": payload.username}


@app.post("/logout")
async def logout():
    active_users.dec()
    return {"message": "Logged out"}


@app.get("/dashboard")
async def dashboard():
    time.sleep(random.uniform(0.01, 0.15))
    return {"panels": ["login_failures", "suspicious_ips", "response_time", "cpu_memory", "vulnerabilities"], "status": "ok"}


@app.get("/api/data")
async def api_data():
    time.sleep(random.uniform(0.005, 0.08))
    return {"data": [random.randint(1, 100) for _ in range(10)]}


# ─── ZAP Ingest ──────────────────────────────

@app.post("/ingest-zap")
async def ingest_zap(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    high = medium = low = informational = 0

    sites = body.get("site", [])
    if isinstance(sites, list):
        for site in sites:
            for alert in site.get("alerts", []):
                risk = alert.get("riskdesc", "").lower()
                if "high" in risk:
                    high += 1
                elif "medium" in risk:
                    medium += 1
                elif "low" in risk:
                    low += 1
                elif "info" in risk:
                    informational += 1

    flat_alerts = body.get("alerts", [])
    if isinstance(flat_alerts, list):
        for alert in flat_alerts:
            risk = alert.get("riskdesc", alert.get("risk", "")).lower()
            if "high" in risk:
                high += 1
            elif "medium" in risk:
                medium += 1
            elif "low" in risk:
                low += 1

    # Save to DB
    try:
        scan = ZapScanResult(high=high, medium=medium, low=low, informational=informational)
        db.add(scan)

        if high > 0:
            db.add(AlertEvent(
                alert_type="high_vulnerability",
                severity="critical",
                message=f"ZAP scan found {high} HIGH severity vulnerability/vulnerabilities"
            ))

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"[DB] Error saving ZAP scan: {e}")

    zap_vulnerabilities_high.set(high)
    zap_vulnerabilities_medium.set(medium)
    zap_vulnerabilities_low.set(low)
    zap_last_scan_timestamp.set(time.time())

    return {"status": "ingested", "counts": {"high": high, "medium": medium, "low": low, "informational": informational}, "timestamp": time.time()}


# ─────────────────────────────────────────────
# Reporting Endpoints
# ─────────────────────────────────────────────

@app.get("/report/summary")
async def report_summary(db: Session = Depends(get_db)):
    """Full security summary report for internship reporting."""
    total_logins = db.query(LoginEvent).count()
    failed_logins = db.query(LoginEvent).filter(LoginEvent.success == False).count()
    successful_logins = db.query(LoginEvent).filter(LoginEvent.success == True).count()
    suspicious_ips = db.query(SuspiciousIP).filter(SuspiciousIP.failed_attempts >= SUSPICIOUS_THRESHOLD).count()
    blocked_ips = db.query(SuspiciousIP).filter(SuspiciousIP.blocked == True).count()
    total_scans = db.query(ZapScanResult).count()
    total_alerts = db.query(AlertEvent).count()
    unresolved_alerts = db.query(AlertEvent).filter(AlertEvent.resolved == False).count()

    latest_scan = db.query(ZapScanResult).order_by(ZapScanResult.timestamp.desc()).first()

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "authentication": {
            "total_login_attempts": total_logins,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "failure_rate_percent": round((failed_logins / total_logins * 100) if total_logins > 0 else 0, 2)
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
                "high": latest_scan.high if latest_scan else 0,
                "medium": latest_scan.medium if latest_scan else 0,
                "low": latest_scan.low if latest_scan else 0,
            }
        },
        "alerts": {
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved_alerts
        }
    }


@app.get("/report/logins")
async def report_logins(limit: int = 50, db: Session = Depends(get_db)):
    """Recent login events log."""
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


@app.get("/report/scans")
async def report_scans(db: Session = Depends(get_db)):
    """ZAP scan history."""
    scans = db.query(ZapScanResult).order_by(ZapScanResult.timestamp.desc()).all()
    return {
        "total_scans": len(scans),
        "scans": [
            {
                "id": s.id,
                "timestamp": s.timestamp.isoformat(),
                "high": s.high,
                "medium": s.medium,
                "low": s.low,
                "informational": s.informational,
                "target": s.target
            } for s in scans
        ]
    }


@app.get("/report/alerts")
async def report_alerts(resolved: Optional[bool] = None, db: Session = Depends(get_db)):
    """Alert event history."""
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


@app.get("/report/suspicious-ips")
async def report_suspicious_ips(db: Session = Depends(get_db)):
    """All tracked suspicious IPs with full history."""
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


@app.patch("/report/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    """Mark an alert as resolved."""
    alert = db.query(AlertEvent).filter(AlertEvent.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()
    return {"message": f"Alert {alert_id} marked as resolved"}


@app.get("/suspicious-ips")
async def get_suspicious_ips():
    suspicious = {ip: count for ip, count in failed_login_tracker.items() if count >= SUSPICIOUS_THRESHOLD}
    return {"suspicious_ips": suspicious, "total": len(suspicious)}
