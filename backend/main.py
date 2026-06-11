import asyncio
import json
import logging
import os
from collections import Counter
from datetime import timedelta
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
from sqlalchemy import case, desc, func
from sqlalchemy.orm import Session as DBSession

from analysis_service import AnalysisService
from behavior_engine import BehaviorEngine
from adaptive_layer import AdaptiveResponseLayer
from database import Base, engine, get_db
from geo_utils import (
    clean_country,
    enrich_ips,
    geo_session_counts,
    has_valid_lat_lng,
    recent_ips_needing_geo,
    to_float,
)
from models import Event, IPIntel, PasswordStat, Session, ThreatReport
from schemas import EventOut, MapAttackPoint, MapHoneypotNode, MapResponse, SessionOut, StatsOut, ThreatReportOut

from ip_enrichment import IPEnrichmentService

app = FastAPI(title="Adaptive Honeypot API", version="0.1.0")
logger = logging.getLogger(__name__)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://159.89.103.231:3001",
        "http://159.89.103.231",
        "http://localhost:3001",
    ],
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
GEO_API_ENRICH_LIMIT = int(os.getenv("GEO_API_ENRICH_LIMIT", "50"))
GEO_REFRESH_HOURS = int(os.getenv("GEO_REFRESH_HOURS", "24"))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_NAME = os.getenv("REDIS_STREAM", "cowrie:events")


@app.on_event("startup")
async def startup() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    Base.metadata.create_all(bind=engine)
    if HAS_REDIS:
        app.state.redis_task = asyncio.create_task(_redis_stream_consumer())
    else:
        logger.info("Redis not installed — skipping stream consumer. WebSocket will only get manual broadcasts.")

@app.on_event("shutdown")
async def shutdown() -> None:
    task = getattr(app.state, "redis_task", None)
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


async def _redis_stream_consumer() -> None:
    """Background task: read from Redis stream and broadcast via WebSocket clients."""
    if not HAS_REDIS or redis is None:
        logger.info("Redis not installed — skipping stream consumer. WebSocket will only get manual broadcasts.")
        return

    logger.info("Redis stream listener started — connecting to %s, stream=%s", REDIS_URL, STREAM_NAME)
    last_id = "$"

    while True:
        client = None
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True)
            logger.info("Redis stream listener connected")
            while True:
                results = await client.xread(
                    {STREAM_NAME: last_id}, count=10, block=5000
                )
                if not results:
                    continue

                for stream_name, entries in results:
                    if stream_name != STREAM_NAME:
                        continue
                    for entry_id, fields in entries:
                        last_id = entry_id
                        logger.info("Received event from Redis stream: %s", entry_id)
                        try:
                            raw = fields.get("event", "{}")
                            event = json.loads(raw)
                        except (json.JSONDecodeError, TypeError) as exc:
                            logger.warning("Failed to parse event JSON from Redis: %s", exc)
                            continue

                        alert = {
                            "type": "event",
                            "data": {
                                "session_id": event.get("session_id", "unknown"),
                                "event_type": event.get("event_type", "unknown"),
                                "raw_command": event.get("raw_command"),
                                "mitre_technique_id": event.get("mitre_technique_id"),
                                "mitre_tactic": event.get("mitre_tactic"),
                                "tactic": event.get("tactic"),
                                "risk_score": event.get("risk_score", 0),
                                "attacker_ip": event.get("attacker_ip", "0.0.0.0"),
                                "timestamp": str(event.get("timestamp", "")),
                                "severity": event.get("severity", "LOW"),
                            }
                        }
                        await manager.broadcast(alert)
                        logger.info("Broadcasted event to %d websocket clients", len(manager.active_connections))

                        # Handle session.closed event
                        if event.get("event_type") in {"cowrie.session.closed", "session.closed"}:
                            await manager.broadcast({
                                "type": "session.closed",
                                "data": {
                                    "session_id": event.get("session_id", "unknown"),
                                    "severity": event.get("severity", "LOW"),
                                    "risk_score": event.get("risk_score", 0),
                                    "duration_seconds": event.get("duration_seconds", 0),
                                    "attacker_ip": event.get("attacker_ip", "0.0.0.0"),
                                }
                            })
                            continue

                        # Handle session.new — comes as a JSON-encoded payload from collector
                        if event.get("type") == "session.new":
                            await manager.broadcast(event)
                            continue

        except asyncio.CancelledError:
            logger.info("Redis stream listener cancelled")
            if client:
                await client.close()
            break
        except Exception as exc:
            logger.error("Redis listener error: %s", exc, exc_info=True)
            if client:
                try:
                    await client.close()
                except Exception:
                    pass
            await asyncio.sleep(5)


# ─── Health ───
@app.get("/health")
@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ─── WebSocket Alerts ───
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket, db: DBSession = Depends(get_db)) -> None:
    await manager.connect(websocket)
    try:
        # Fetch last 50 events
        events = (
            db.query(Event, Session)
            .join(Session, Event.session_id == Session.session_id)
            .order_by(desc(Event.timestamp))
            .limit(50)
            .all()
        )
        
        history_events = []
        for ev, sess in events:
            history_events.append({
                "session_id": ev.session_id,
                "event_type": ev.event_type,
                "raw_command": ev.raw_command,
                "mitre_technique_id": ev.mitre_technique,
                "mitre_tactic": ev.mitre_tactic,
                "tactic": sess.current_tactic,
                "risk_score": sess.risk_score,
                "attacker_ip": sess.attacker_ip,
                "timestamp": ev.timestamp.isoformat(),
                "severity": sess.severity,
            })
        
        # Fetch all active sessions (end_time IS NULL)
        active_sessions = (
            db.query(Session)
            .filter(Session.end_time.is_(None))
            .order_by(desc(Session.start_time))
            .limit(50)
            .all()
        )
        
        history_sessions = []
        for s in active_sessions:
            history_sessions.append({
                "session_id": s.session_id,
                "attacker_ip": s.attacker_ip,
                "start_time": s.start_time.isoformat() if s.start_time else None,
                "risk_score": s.risk_score,
                "severity": s.severity,
                "current_tactic": s.current_tactic,
                "login_attempts": s.login_attempts,
                "duration_seconds": s.duration_seconds,
            })
            
        await websocket.send_json({
            "type": "history",
            "data": {
                "events": history_events,
                "sessions": history_sessions,
            }
        })
        
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
async def get_stats(db: DBSession = Depends(get_db)) -> StatsOut:
    await _enrich_missing_recent_geo(db, reason="/api/stats")

    top_ips = [
        {"ip": ip, "count": count}
        for ip, count in db.query(Session.attacker_ip, func.count(Session.id)).group_by(Session.attacker_ip).order_by(desc(func.count(Session.id))).limit(10)
    ]
    country_counts: Counter[str] = Counter()
    country_rows = (
        db.query(Session.attacker_ip, IPIntel.country_name)
        .outerjoin(IPIntel, IPIntel.ip == Session.attacker_ip)
        .all()
    )
    for _, country in country_rows:
        known_country = clean_country(country)
        if known_country:
            country_counts[known_country] += 1
    top_countries = [
        {"country": country, "count": count}
        for country, count in country_counts.most_common(10)
    ]
    top_tactics = [
        {"tactic": tactic, "count": count}
        for tactic, count in db.query(Session.current_tactic, func.count(Session.id)).group_by(Session.current_tactic).order_by(desc(func.count(Session.id))).limit(10)
    ]
    top_passwords = [
        {"password": password, "count": count}
        for password, count in db.query(PasswordStat.password, PasswordStat.attempt_count).order_by(desc(PasswordStat.attempt_count)).limit(20)
    ]
    debug_counts = geo_session_counts(db)
    logger.info(
        "/api/stats geo debug: total_sessions=%d sessions_with_country=%d sessions_with_valid_lat_lng=%d",
        debug_counts["total_sessions"],
        debug_counts["sessions_with_country"],
        debug_counts["sessions_with_valid_lat_lng"],
    )

    return StatsOut(
        total_attacks=db.query(Session).count(),
        top_ips=top_ips,
        top_countries=top_countries,
        top_tactics=top_tactics,
        top_passwords=top_passwords,
    )

# ─── Map ───
@app.get("/api/map", response_model=MapResponse)
async def map_data(db: DBSession = Depends(get_db)) -> MapResponse:
    await _enrich_missing_recent_geo(db, reason="/api/map")

    honeypot = MapHoneypotNode(
        lat=51.17,
        lng=71.45,
        city="Astana",
        country="Kazakhstan",
    )

    attacks: list[MapAttackPoint] = []
    unknown_locations = 0
    try:
        severity_rank = case(
            (Session.severity == "CRITICAL", 4),
            (Session.severity == "HIGH", 3),
            (Session.severity == "MEDIUM", 2),
            (Session.severity == "LOW", 1),
            else_=1,
        )
        rows = (
            db.query(
                Session.attacker_ip,
                IPIntel.country_name,
                IPIntel.city,
                IPIntel.latitude,
                IPIntel.longitude,
                IPIntel.asn,
                IPIntel.org_name,
                func.count(Session.id).label("attack_count"),
                func.max(Session.risk_score).label("risk_score"),
                func.max(severity_rank).label("severity_rank"),
                func.max(Session.start_time).label("last_seen"),
                func.max(Session.session_id).label("session_id"),
                func.max(Session.current_tactic).label("current_tactic"),
            )
            .outerjoin(IPIntel, IPIntel.ip == Session.attacker_ip)
            .group_by(
                Session.attacker_ip,
                IPIntel.country_name,
                IPIntel.city,
                IPIntel.latitude,
                IPIntel.longitude,
                IPIntel.asn,
                IPIntel.org_name,
            )
            .order_by(desc(func.max(Session.start_time)))
            .limit(1000)
            .all()
        )

        for row in rows:
            try:
                lat = to_float(row.latitude)
                lng = to_float(row.longitude)
                if not has_valid_lat_lng(lat, lng):
                    unknown_locations += int(row.attack_count or 0)
                    continue
                attacks.append(MapAttackPoint(
                    ip=row.attacker_ip,
                    country=clean_country(row.country_name) or "unknown",
                    lat=lat,
                    lng=lng,
                    severity=_severity_from_rank(row.severity_rank),
                    count=int(row.attack_count or 0),
                    city=row.city or "",
                    risk_score=int(row.risk_score or 0),
                    session_id=row.session_id,
                    asn=row.asn or "",
                    org=row.org_name or "",
                    current_tactic=row.current_tactic or "",
                    timestamp=row.last_seen,
                ))
            except Exception as exc:
                logger.warning("Skipping map attack point for IP %s: %s", row.attacker_ip, exc)
                continue
    except Exception as exc:
        logger.error("Failed to build map attack list: %s", exc, exc_info=True)
        # Return empty attacks — map will show "no data" instead of crashing

    debug_counts = geo_session_counts(db)
    logger.info(
        "/api/map geo debug: total_sessions=%d sessions_with_country=%d sessions_with_valid_lat_lng=%d points_sent=%d unknown_locations=%d",
        debug_counts["total_sessions"],
        debug_counts["sessions_with_country"],
        debug_counts["sessions_with_valid_lat_lng"],
        len(attacks),
        unknown_locations,
    )
    return MapResponse(
        attacks=attacks,
        honeypot=honeypot,
        unknown_locations=unknown_locations,
        debug={**debug_counts, "points_sent": len(attacks), "unknown_locations": unknown_locations},
    )


async def _enrich_missing_recent_geo(db: DBSession, *, reason: str) -> None:
    ips = recent_ips_needing_geo(
        db,
        limit=GEO_API_ENRICH_LIMIT,
        refresh_after=timedelta(hours=GEO_REFRESH_HOURS),
    )
    if not ips:
        return
    result = await enrich_ips(db, ips, service=ip_enrichment_service)
    logger.info(
        "%s geo enrichment: candidate_ips=%d attempted=%d stored=%d failed=%d",
        reason,
        len(ips),
        result["attempted"],
        result["stored"],
        result["failed"],
    )


def _severity_from_rank(rank: int | None) -> str:
    if rank == 4:
        return "CRITICAL"
    if rank == 3:
        return "HIGH"
    if rank == 2:
        return "MEDIUM"
    return "LOW"


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
async def export_threat(report_id: UUID, db: DBSession = Depends(get_db)) -> FileResponse:
    report = db.query(ThreatReport).filter(ThreatReport.id == report_id).one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Threat report not found")
    session = db.query(Session).filter(Session.session_id == report.session_id).one()
    events = db.query(Event).filter(Event.session_id == report.session_id).order_by(Event.timestamp).all()
    path = report.pdf_path
    if not path or not Path(path).exists():
        path = await analysis_service.pdf_exporter.export(
            analysis_service.model_to_dict(report),
            analysis_service.model_to_dict(session),
            [analysis_service.model_to_dict(event) for event in events],
        )
        report.pdf_path = path
        db.commit()
        
    filename = Path(path).name
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return FileResponse(path, media_type="application/pdf", filename=filename, headers=headers)


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


# ─── Session Reclassification (for existing sessions) ───
@app.post("/api/sessions/reclassify")
def reclassify_sessions(
    db: DBSession = Depends(get_db),
    limit: int = Query(500, ge=1, le=5000),
) -> dict[str, Any]:
    """Re-run tactic classification for existing sessions based on their event logs.

    This fixes the legacy data issue where all sessions showed
    TACTIC=DEFENSE_EVASION and ADAPTATION=RICH_FAKE_FILESYSTEM.
    New sessions are not affected — they use the corrected logic
    in collector.py.
    """
    behavior = BehaviorEngine()
    adaptive = AdaptiveResponseLayer(os.getenv("COWRIE_HONEYFS_ROOT", "/opt/cowrie/honeyfs"))

    sessions = db.query(Session).order_by(desc(Session.start_time)).limit(limit).all()
    updated = 0
    skipped = 0

    for session in sessions:
        events = (
            db.query(Event)
            .filter(Event.session_id == session.session_id)
            .order_by(Event.timestamp)
            .all()
        )

        if not events:
            skipped += 1
            continue

        event_dicts = [
            {
                "event_type": ev.event_type,
                "raw_command": ev.raw_command or "",
                "timestamp": ev.timestamp,
            }
            for ev in events
        ]

        profile = behavior.build_session_profile(event_dicts)
        new_tactic = profile.get("current_tactic")
        new_risk = profile.get("risk_score", 0)
        new_severity = profile.get("severity", "LOW")
        new_history = profile.get("tactic_history", [])

        if new_tactic and new_tactic != session.current_tactic:
            session.current_tactic = new_tactic
            session.risk_score = new_risk
            session.severity = new_severity
            session.tactic_history = new_history
            session.adaptation_applied = adaptive.apply(new_tactic, new_severity)
            updated += 1
        elif new_risk != session.risk_score or new_severity != session.severity:
            session.risk_score = new_risk
            session.severity = new_severity
            session.tactic_history = new_history
            updated += 1
        else:
            skipped += 1

    db.commit()

    logger.info(
        "Reclassification complete: updated=%d skipped=%d total=%d",
        updated,
        skipped,
        len(sessions),
    )
    return {
        "updated": updated,
        "skipped": skipped,
        "total": len(sessions),
    }
