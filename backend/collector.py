import asyncio
import json
import logging
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session as DBSession

from adaptive_layer import AdaptiveResponseLayer
from analysis_service import AnalysisService
from behavior_engine import BehaviorEngine
from database import SessionLocal
from models import Event, IPIntel, PasswordStat, Session, ThreatReport

logger = logging.getLogger(__name__)

PENDING_ANALYSIS_MARKER = "__pending_analysis"


class CowrieCollector:
    def __init__(self) -> None:
        self.log_path = Path(os.getenv("COWRIE_JSON_LOG", "/var/log/cowrie/cowrie.json"))
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.stream_name = os.getenv("REDIS_STREAM", "cowrie:events")
        self.behavior = BehaviorEngine()
        self.adaptive = AdaptiveResponseLayer(os.getenv("COWRIE_HONEYFS_ROOT", "/opt/cowrie/honeyfs"))
        self._last_session_seen: dict[str, datetime] = {}
        # In-memory set of session IDs currently being analyzed.
        # Persistence is handled by the PENDING_ANALYSIS_MARKER in the DB.
        self._finalize_inflight: set[str] = set()
        self.analysis_service = AnalysisService(
            output_dir=os.getenv("REPORT_OUTPUT_DIR", "/app/reports"),
        )

    async def run(self) -> None:
        client = redis.from_url(self.redis_url, decode_responses=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.touch(exist_ok=True)

        # Resume any unprocessed sessions from a previous collector crash
        await self._resume_pending_analyses()

        with self.log_path.open("r", encoding="utf-8") as log_file:
            log_file.seek(0, os.SEEK_END)
            while True:
                batch = []
                # Read up to 50 lines at once to reduce DB round trips
                for _ in range(50):
                    line = log_file.readline()
                    if not line:
                        break
                    batch.append(line)

                if not batch:
                    await asyncio.sleep(0.2)  # shorter sleep = more responsive
                    continue

                await self.process_batch(batch, client)

    async def process_batch(self, lines: list[str], client: redis.Redis) -> None:
        """Process multiple log lines in a single DB session and Redis pipeline."""
        normalized_events = []
        session_closed_ids = []

        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            normalized = self.normalize_event(event)
            normalized_events.append(normalized)

            if normalized.get("event_type") in {"cowrie.session.closed", "session.closed"}:
                session_closed_ids.append(normalized["session_id"])

        if not normalized_events:
            return

        # Single DB session for the whole batch
        with SessionLocal() as db:
            for normalized in normalized_events:
                self.save_event(db, normalized)
            db.commit()

        # Redis pipeline: single round trip for all events
        async with client.pipeline() as pipe:
            for normalized in normalized_events:
                pipe.xadd(self.stream_name, {"event": json.dumps(normalized, default=str)}, maxlen=10000)
            await pipe.execute()

        # Schedule analysis for closed sessions
        for session_id in session_closed_ids:
            self.schedule_finalize(session_id)

    async def _resume_pending_analyses(self) -> None:
        """On startup, find any sessions that were marked as pending analysis
        but have no threat report yet, and finalize them.
        This solves the persistence gap when the collector restarts
        before a previous asyncio.create_task finished."""
        try:
            with SessionLocal() as db:
                pending = (
                    db.query(Session)
                    .filter(
                        Session.adaptation_applied == PENDING_ANALYSIS_MARKER,
                        ~Session.session_id.in_(
                            db.query(ThreatReport.session_id).filter(
                                ThreatReport.session_id == Session.session_id
                            )
                        ),
                    )
                    .all()
                )
                for session in pending:
                    logger.info("Resuming pending analysis for session %s", session.session_id)
                    self._finalize_inflight.add(session.session_id)
                    asyncio.create_task(self._run_analysis(session.session_id))
        except Exception as exc:
            logger.warning("Failed to resume pending analyses: %s", exc)

    def schedule_finalize(self, session_id: str) -> None:
        if session_id in self._finalize_inflight:
            return
        self._finalize_inflight.add(session_id)

        # Persist pending marker in DB so analysis survives restarts.
        # Only set if the session hasn't already been given a real adaptation.
        with SessionLocal() as db:
            session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
            if session and session.adaptation_applied is None:
                session.adaptation_applied = PENDING_ANALYSIS_MARKER
                db.commit()

        asyncio.create_task(self._run_analysis(session_id))

    async def _run_analysis(self, session_id: str) -> None:
        """Run the full analysis pipeline using the shared AnalysisService."""
        try:
            with SessionLocal() as db:
                existing = db.query(ThreatReport).filter(ThreatReport.session_id == session_id).one_or_none()
                if existing:
                    return

                session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
                if not session:
                    return

                events = db.query(Event).filter(Event.session_id == session_id).order_by(Event.timestamp).all()
                intel = db.query(IPIntel).filter(IPIntel.ip == session.attacker_ip).one_or_none()

                report = await self.analysis_service.analyze_and_report(session, events, intel, db)

                # Clear the pending marker
                if session.adaptation_applied == PENDING_ANALYSIS_MARKER:
                    session.adaptation_applied = None
                db.commit()

                logger.info("Analysis complete for session %s (severity=%s)", session_id, report.severity)
        except Exception as exc:
            logger.error("Analysis failed for session %s: %s", session_id, exc, exc_info=True)
        finally:
            self._finalize_inflight.discard(session_id)

    def normalize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        timestamp = self.parse_timestamp(event.get("timestamp"))
        return {
            "session_id": event.get("session") or event.get("session_id") or "unknown",
            "attacker_ip": event.get("src_ip") or event.get("attacker_ip") or "0.0.0.0",
            "event_type": event.get("eventid") or event.get("event_type") or "unknown",
            "username": event.get("username"),
            "password": event.get("password"),
            "raw_command": event.get("input") or event.get("command"),
            "event_data": event,
            "timestamp": timestamp,
        }

    def save_event(self, db: DBSession, event: dict[str, Any]) -> None:
        session = self.upsert_session(db, event)
        failed_logins = self.recent_failed_login_times(db, event["session_id"])
        classified = self.behavior.classify_event(
            {
                "event_type": event["event_type"],
                "raw_command": event.get("raw_command") or "",
                "timestamp": event["timestamp"],
            },
            failed_logins,
        )

        is_session_close = event["event_type"] in {"cowrie.session.closed", "session.closed"}

        db.add(
            Event(
                session_id=event["session_id"],
                event_type=event["event_type"],
                event_data=event["event_data"],
                raw_command=event.get("raw_command"),
                mitre_technique=classified.get("mitre_technique_id"),
                mitre_tactic=classified.get("mitre_tactic"),
                timestamp=event["timestamp"],
            )
        )

        if event["event_type"] in {"cowrie.login.failed", "login.failed"}:
            session.login_attempts += 1
            self.update_password_stat(db, event.get("password"))
        if event["event_type"] in {"cowrie.login.success", "login.success"}:
            session.successful_login = True
        if is_session_close:
            session.end_time = event["timestamp"]
            if session.start_time:
                session.duration_seconds = int((session.end_time - session.start_time).total_seconds())
            # On session close, reclassify based on overall session stats
            self._finalize_session_classification(db, session)

        # Append per-event tactic to history for detail tracking (not used for final tactic)
        tactic = classified.get("tactic")
        if tactic and tactic not in {"UNKNOWN", "LOGIN_FAILED"} and not is_session_close:
            self._append_event_to_history(session, tactic, classified, event["timestamp"])

        event["mitre_technique_id"] = classified.get("mitre_technique_id")
        event["mitre_tactic"] = classified.get("mitre_tactic")
        event["tactic"] = classified.get("tactic")
        event["risk_score"] = session.risk_score
        event["severity"] = session.severity
        event["duration_seconds"] = getattr(session, "duration_seconds", 0)

    def upsert_session(self, db: DBSession, event: dict[str, Any]) -> Session:
        session_id = event["session_id"]
        now = event["timestamp"]
        last_seen = self._last_session_seen.get(session_id)
        self._last_session_seen[session_id] = now

        session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
        if session:
            return session

        if last_seen and now - last_seen < timedelta(minutes=1):
            session = db.query(Session).filter(Session.session_id == session_id).one_or_none()
            if session:
                return session

        # Check SQLAlchemy identity map for a session added earlier in this batch before flush.
        for obj in db.new:
            if isinstance(obj, Session) and obj.session_id == session_id:
                return obj

        session = Session(session_id=session_id, attacker_ip=event["attacker_ip"], start_time=now)
        db.add(session)
        db.flush()

        # Broadcast session.new into Redis stream so that main.py can forward it to WebSocket clients.
        # This runs outside the DB session to avoid holding the connection open.
        asyncio.create_task(self._broadcast_new_session(session, event["attacker_ip"]))
        return session

    async def _broadcast_new_session(self, session: Session, attacker_ip: str) -> None:
        """Push a session.new event to Redis for WebSocket broadcast."""
        try:
            client = redis.from_url(self.redis_url, decode_responses=True)
            payload = json.dumps({
                "type": "session.new",
                "data": {
                    "session_id": session.session_id,
                    "attacker_ip": attacker_ip,
                    "start_time": session.start_time.isoformat(),
                    "risk_score": 0,
                    "severity": "LOW",
                    "current_tactic": None,
                    "login_attempts": 0,
                }
            }, default=str)
            await client.xadd(self.stream_name, {"event": payload}, maxlen=10000)
            await client.aclose()
        except Exception as exc:
            logger.warning("Failed to broadcast session.new: %s", exc)

    def recent_failed_login_times(self, db: DBSession, session_id: str) -> list[datetime]:
        since = datetime.utcnow() - timedelta(minutes=1)
        rows = (
            db.query(Event.timestamp)
            .filter(Event.session_id == session_id)
            .filter(Event.event_type.in_(["cowrie.login.failed", "login.failed"]))
            .filter(Event.timestamp >= since)
            .all()
        )
        return [row[0] for row in rows if row[0]]

    def _append_event_to_history(self, session: Session, tactic: str, classified: dict[str, Any], timestamp: datetime) -> None:
        """Append a per-event tactic entry to the session's tactic_history.
        This is used for detail/audit only — the final session tactic
        is determined by _finalize_session_classification().
        """
        history = list(session.tactic_history or [])
        history.append(
            {
                "tactic": tactic,
                "timestamp": timestamp.isoformat(),
                "mitre_technique_id": classified.get("mitre_technique_id"),
                "risk_score": classified.get("risk_score", 0),
            }
        )
        session.tactic_history = history

        # Maintain accumulative risk_score for display during live session
        entry_risk = classified.get("risk_score", 0)
        if not session.risk_score:
            session.risk_score = 0
        session.risk_score = min(100, (session.risk_score or 0) + entry_risk)
        session.severity = self.behavior.severity_from_score(session.risk_score)

    def _finalize_session_classification(self, db: DBSession, session: Session) -> None:
        """When a session closes, reclassify it based on overall session stats.

        Uses BehaviorEngine.classify_session() which looks at login count,
        command count, duration, and connection frequency to produce a
        more accurate MITRE tactic than per-event classification.
        """
        # Count how many sessions this IP has (for PERSISTENCE detection)
        ip_session_count = (
            db.query(func.count(Session.id))
            .filter(Session.attacker_ip == session.attacker_ip)
            .scalar()
        ) or 1

        # Extract command tactics from the events
        events = (
            db.query(Event)
            .filter(Event.session_id == session.session_id)
            .filter(Event.event_type.in_(["cowrie.command.input", "command.input"]))
            .filter(Event.raw_command.isnot(None))
            .all()
        )
        command_tactics = []
        for ev in events:
            ct = self.behavior.command_to_tactic(ev.raw_command)
            if ct and ct != "UNKNOWN":
                command_tactics.append(ct)

        result = self.behavior.classify_session(
            login_attempts=session.login_attempts or 0,
            successful_login=bool(session.successful_login),
            command_count=len(events),
            duration_seconds=session.duration_seconds or 0,
            session_count_from_ip=ip_session_count,
            command_tactics=command_tactics,
        )

        new_tactic = result.get("tactic")
        new_risk = result.get("risk_score", 0)
        new_severity = result.get("severity", "LOW")

        previous = session.current_tactic
        session.current_tactic = new_tactic

        # Merge: keep the higher of accumulated per-event risk vs session-level risk
        accumulated_risk = session.risk_score or 0
        session.risk_score = max(new_risk, accumulated_risk)
        session.severity = self.behavior.severity_from_score(session.risk_score)

        # Apply adaptation when tactic is known
        if new_tactic and new_tactic != "UNKNOWN":
            session.adaptation_applied = self.adaptive.apply(new_tactic, session.severity)
        elif session.adaptation_applied in (None, PENDING_ANALYSIS_MARKER):
            session.adaptation_applied = self.adaptive.apply("RECONNAISSANCE", session.severity)

    def update_password_stat(self, db: DBSession, password: str | None) -> None:
        if not password:
            return
        stmt = insert(PasswordStat).values(password=password, attempt_count=1)
        stmt = stmt.on_conflict_do_update(
            index_elements=[PasswordStat.password],
            set_={
                "attempt_count": PasswordStat.attempt_count + 1,
                "last_seen": func.now(),
            },
        )
        db.execute(stmt)

    def parse_timestamp(self, value: str | None) -> datetime:
        if not value:
            return datetime.now(UTC).replace(tzinfo=None)
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


async def main() -> None:
    await CowrieCollector().run()


if __name__ == "__main__":
    asyncio.run(main())
