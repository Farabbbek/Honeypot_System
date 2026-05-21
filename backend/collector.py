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
                session.adaptation_applied = None if session.adaptation_applied == PENDING_ANALYSIS_MARKER else session.adaptation_applied
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
        if event["event_type"] in {"cowrie.session.closed", "session.closed"}:
            session.end_time = event["timestamp"]
            if session.start_time:
                session.duration_seconds = int((session.end_time - session.start_time).total_seconds())

        tactic = classified.get("tactic")
        if tactic and tactic not in {"UNKNOWN", "LOGIN_FAILED"}:
            self.update_session_profile(session, tactic, classified, event["timestamp"])

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

        session = Session(session_id=session_id, attacker_ip=event["attacker_ip"], start_time=now)
        db.add(session)
        db.flush()
        return session

    def recent_failed_login_times(self, db: DBSession, session_id: str) -> list[datetime]:
        since = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)
        rows = (
            db.query(Event.timestamp)
            .filter(Event.session_id == session_id)
            .filter(Event.event_type.in_(["cowrie.login.failed", "login.failed"]))
            .filter(Event.timestamp >= since)
            .all()
        )
        return [row[0] for row in rows if row[0]]

    def update_session_profile(self, session: Session, tactic: str, classified: dict[str, Any], timestamp: datetime) -> None:
        history = list(session.tactic_history or [])
        previous = session.current_tactic
        history.append(
            {
                "tactic": tactic,
                "timestamp": timestamp.isoformat(),
                "mitre_technique_id": classified.get("mitre_technique_id"),
            }
        )
        session.tactic_history = history
        session.current_tactic = tactic
        session.risk_score = min(100, session.risk_score + classified.get("risk_score", 0))
        session.severity = self.behavior.severity_from_score(session.risk_score)
        if previous != tactic:
            if session.adaptation_applied in (None, PENDING_ANALYSIS_MARKER):
                session.adaptation_applied = self.adaptive.apply(tactic)

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