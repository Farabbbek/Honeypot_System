import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any
from uuid import UUID

try:
    import redis.asyncio as redis
    HAS_REDIS = True
except ImportError:
    redis = None
    HAS_REDIS = False
from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy import desc, func
from sqlalchemy.orm import Session as DBSession

from analysis_service import AnalysisService
from database import Base, engine, get_db
from models import Event, IPIntel, PasswordStat, Session, ThreatReport
from schemas import EventOut, SessionOut, StatsOut, ThreatReportOut

from ip_enrichment import IPEnrichmentService

app = FastAPI(title="Adaptive Honeypot API", version="0.1.0")
logger = logging.getLogger(__name__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                dead.append(connection)
        for d in dead:
            self.active_connections.remove(d)


manager = ConnectionManager()
analysis_service = AnalysisService(
    output_dir=os.getenv("REPORT_OUTPUT_DIR", "/app/reports"),
)
ip_enrichment_service = IPEnrichmentService()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = os.getenv("REDIS_STREAM", "cowrie:events")


@app.on_event("startup")
async def startup() -> None:
    Base.metadata.create_all(bind=engine)
    # Start Redis consumer in background
    """Background task: read from Redis stream and broadcast via WebSocket."""
    if HAS_REDIS:
        asyncio.create_task(_redis_stream_consumer())
    else:
        logger.info("Redis not installed — skipping stream consumer. WebSocket will only get manual broadcasts.")


async def _redis_stream_consumer() -> None:
    """Consume cowrie:events from Redis and broadcast normalized alerts to WebSocket clients."""
    if not HAS_REDIS or redis is None:
        return
    last_id = "$"
    while True:
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True)
            while True:
                try:
                    results = await client.xread(
                        {STREAM_NAME: last_id}, count=10, block=500
                    )
                except Exception:
                    await asyncio.sleep(1)
                    continue

                if not results:
                    continue

                for stream_name, entries in results:
                    if stream_name != STREAM_NAME:
                        continue
                    for entry_id, fields in entries:
                        last_id = entry_id
                        try:
                            raw = fields.get("event", "{}")
                            event = json.loads(raw)
                        except (json.JSONDecodeError, TypeError):
                            continue

                        alert = {
                            "type": "attack_alert",
                            "session_id": event.get("session_id", "unknown"),
                            "timestamp": str(event.get("timestamp", "")),
                            "severity": event.get("severity", "LOW"),
                            "ip": event.get("attacker_ip", "0.0.0.0"),
                            "event_type": event.get("event_type", "unknown"),
                            "message": event.get("raw_command", ""),
                            "attack_type": event.get("mitre_technique", "UNKNOWN"),
                        }
                        await manager.broadcast(alert)

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Redis consumer error: %s", exc, exc_info=True)
            await asyncio.sleep(3)


# ─── Health ───
@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ─── WebSocket Alerts ───
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─── Sessions ───
@app.get("/api/sessions", response_model=list[SessionOut])
def list_sessions(
    db: DBSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tactic: str | None = None,
    country: str | None = None,
    severity: str | None = None,
) -> list[Session]:
    query = db.query(Session)
    if tactic:
        query = query.filter(Session.current_tactic == tactic)
    if severity:
        query = query.filter(Session.severity == severity.upper())
    if country:
        query = query.join(IPIntel, IPIntel.ip == Session.attacker_ip).filter(IPIntel.country_code == country.upper())
    return query.order_by(desc(Session.start_time)).offset(offset).limit(limit).all()


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str, db: DBSession = Depends(get_db)) -> dict[str, Any]:
    session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.timestamp).all()
    report = db.query(ThreatReport).filter(ThreatReport.session_id == session_id).order_by(desc(ThreatReport.created_at)).first()
    intel = db.query(IPIntel).filter(IPIntel.ip == session.attacker_ip).one_or_none()
    return {
        "session": SessionOut.model_validate(session),
        "events": [EventOut.model_validate(event) for event in events],
        "report": ThreatReportOut.model_validate(report) if report else None,
        "ip_intel": analysis_service.model_to_dict(intel) if intel else None,
    }


# ─── Stats ───
@app.get("/api/stats", response_model=StatsOut)
def get_stats(db: DBSession = Depends(get_db)) -> StatsOut:
    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in db.query(Session.attacker_ip, func.count(Session.id)).group_by(Session.attacker_ip).order_by(desc(func.count(Session.id))).limit(10)
    ]
    top_countries = [
        {"country": country, "count": count}
        for country, count in db.query(IPIntel.country_name, func.count(IPIntel.id)).group_by(IPIntel.country_name).order_by(desc(func.count(IPIntel.id))).limit(10)
    ]
    top_tactics = [
        {"tactic": tactic, "count": count}
        for tactic, count in db.query(Session.current_tactic, func.count(Session.id)).group_by(Session.current_tactic).order_by(desc(func.count(Session.id))).limit(10)
    ]
    top_passwords = [
        {"password": password, "count": count}
        for password, count in db.query(PasswordStat.password, PasswordStat.attempt_count).order_by(desc(PasswordStat.attempt_count)).limit(20)
    ]
    return StatsOut(
        total_attacks=db.query(Session).count(),
        top_ips=top_ips,
        top_countries=top_countries,
        top_tactics=top_tactics,
        top_passwords=top_passwords,
    )


# ─── Map ───
@app.get("/api/map")
def map_data(db: DBSession = Depends(get_db)) -> list[dict[str, Any]]:
    rows = (
        db.query(Session, IPIntel)
        .join(IPIntel, IPIntel.ip == Session.attacker_ip)
        .filter(IPIntel.latitude.isnot(None), IPIntel.longitude.isnot(None))
        .order_by(desc(Session.start_time))
        .limit(1000)
        .all()
    )
    return [
        {
            "session_id": session.session_id,
            "ip": session.attacker_ip,
            "latitude": intel.latitude,
            "longitude": intel.longitude,
            "country": intel.country_name,
            "city": intel.city,
            "severity": session.severity,
            "risk_score": session.risk_score,
            "asn": intel.asn or "",
            "org": intel.org_name or "",
            "tactics": session.tactic_history if isinstance(session.tactic_history, list) else [],
            "current_tactic": session.current_tactic or "",
        }
        for session, intel in rows
    ]


# ─── GeoIP Enrichment ───
@app.get("/api/geoip/{ip:path}")
async def geoip_lookup(ip: str) -> dict[str, Any]:
    """Real-time GeoIP enrichment for a given IP address."""
    if not ip or ip == "undefined":
        raise HTTPException(status_code=400, detail="Invalid IP")
    try:
        data = await ip_enrichment_service.enrich(ip)
        return data
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"GeoIP lookup failed: {exc}")


@app.get("/api/geoip/batch")
async def geoip_batch(
    db: DBSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    """Get enriched geo-location data for the most recent unique attacker IPs."""
    recent_ips = (
        db.query(Session.attacker_ip)
        .distinct()
        .order_by(desc(Session.start_time))
        .limit(limit)
        .all()
    )
    ips = [row[0] for row in recent_ips]
    intel_records = db.query(IPIntel).filter(IPIntel.ip.in_(ips)).all()
    intel_map = {r.ip: r for r in intel_records}
    result = []
    for ip in ips:
        rec = intel_map.get(ip)
        if rec:
            result.append({
                "ip": rec.ip,
                "country": rec.country_name,
                "city": rec.city,
                "latitude": rec.latitude,
                "longitude": rec.longitude,
                "asn": rec.asn,
                "org": rec.org_name,
            })
    return result


# ─── Threats ───
@app.get("/api/threats", response_model=list[ThreatReportOut])
def list_threats(db: DBSession = Depends(get_db), limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)) -> list[ThreatReport]:
    return db.query(ThreatReport).order_by(desc(ThreatReport.created_at)).offset(offset).limit(limit).all()


@app.post("/api/threats/{session_id}/analyze", response_model=ThreatReportOut)
async def analyze_session(session_id: str, db: DBSession = Depends(get_db)) -> ThreatReport:
    session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.timestamp).all()
    intel = db.query(IPIntel).filter(IPIntel.ip == session.attacker_ip).one_or_none()

    report = await analysis_service.analyze_and_report(session, events, intel, db)

    await manager.broadcast({"type": "threat_report", "session_id": session_id, "severity": report.severity})
    return report


@app.get("/api/threats/{report_id}/export")
def export_threat(report_id: UUID, db: DBSession = Depends(get_db)) -> FileResponse:
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")
    session = db.query(Session).filter(Session.session_id == report.session_id).one()
    events = db.query(Event).filter(Event.session_id == report.session_id).order_by(Event.timestamp).all()
    path = report.pdf_path
    if not path or not Path(path).exists():
        path = analysis_service.pdf_exporter.export(
            analysis_service.model_to_dict(report),
            analysis_service.model_to_dict(session),
            [analysis_service.model_to_dict(event) for event in events],
        )
        report.pdf_path = path
        db.commit()
    return FileResponse(path, media_type="application/pdf", filename=Path(path).name)


@app.post("/api/threats/{report_id}/notify")
async def notify_threat(report_id: UUID, db: DBSession = Depends(get_db)) -> dict[str, Any]:
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")

    payload = analysis_service.model_to_dict(report)
    sent = await analysis_service.notifier.send_attack_alert(payload)
    report.notification_sent = sent
    db.commit()
    return {"sent": sent, "report_id": str(report_id), "error": analysis_service.notifier.last_error}


@app.get("/api/telegram/diagnose")
async def telegram_diagnose() -> dict[str, Any]:
    return await analysis_service.notifier.diagnose()