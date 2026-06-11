"""
Shared analysis service used by both collector.py and main.py.

Eliminates code duplication for:
- IP enrichment
- LLM report generation
- ThreatReport creation
- PDF export
- Telegram notification
"""

import asyncio
import inspect
import logging
from typing import Any

from sqlalchemy.orm import Session as DBSession

from geo_utils import normalize_enrichment_payload, upsert_ip_intel
from ip_enrichment import IPEnrichmentService
from llm_agent import LLMAgent
from models import IPIntel, Session, ThreatReport
from notifier import TelegramNotifier
from pdf_export import PDFExporter

logger = logging.getLogger(__name__)
AUTO_NOTIFY_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}

# ── Noise Filter Tuning ──
MIN_ALERT_RISK_SCORE = 40
MIN_COMMAND_COUNT = 1
NOISE_MAX_DURATION_SECONDS = 2

# Events that bots typically produce — not indicative of real attacker activity
LOW_VALUE_EVENT_TYPES = {
    "cowrie.session.connect",
    "cowrie.client.version",
    "cowrie.client.kex",
    "cowrie.login.success",
    "cowrie.login.failed",
    "cowrie.session.closed",
    "session.connect",
    "client.version",
    "client.kex",
    "login.success",
    "login.failed",
    "session.closed",
}

# Tactics that indicate real attacker behavior (MITRE ATT&CK)
ALERT_WORTHY_TACTICS = {
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "DEFENSE_EVASION",
    "CREDENTIAL_ACCESS",
    "DISCOVERY",
    "LATERAL_MOVEMENT",
    "COLLECTION",
    "EXFILTRATION",
}

# Suspicious keywords in commands that indicate real attacker activity
SUSPICIOUS_KEYWORDS = [
    "wget",
    "curl",
    "chmod",
    "scp",
    "tftp",
    "nc",
    "bash",
    "sh",
    "python",
    "perl",
    "/etc/passwd",
    "/etc/shadow",
    "crontab",
    "whoami",
    "uname",
    "id",
    "cat",
    "tar",
]


def should_send_telegram_alert(session: Session, events: list[Any]) -> bool:
    """Return True if this session warrants a Telegram notification.

    Filters out bot/noise sessions that only connect, try credentials,
    and disconnect without executing any commands.
    """
    session_id = getattr(session, "session_id", "unknown")
    risk_score = getattr(session, "risk_score", 0) or 0
    severity = (getattr(session, "severity", "LOW") or "LOW").upper()
    tactic = (getattr(session, "current_tactic", "") or "").upper()
    duration = getattr(session, "duration_seconds", 0) or 0

    # Extract commands and event types
    commands: list[str] = []
    event_types: set[str] = set()

    for ev in events:
        et = (getattr(ev, "event_type", "") or "").lower()
        event_types.add(et)
        cmd = getattr(ev, "raw_command", None)
        if cmd and isinstance(cmd, str) and cmd.strip():
            commands.append(cmd.strip())

    command_count = len(commands)

    # ── ALERT-WORTHY checks (short-circuit, return True) ──

    # At least one command executed
    if command_count >= MIN_COMMAND_COUNT:
        logger.info(
            "Sending Telegram alert for interactive attacker session %s (%d commands)",
            session_id,
            command_count,
        )
        return True

    # Risk score threshold
    if risk_score >= MIN_ALERT_RISK_SCORE:
        logger.info(
            "Sending Telegram alert for high-risk session %s (risk_score=%d)",
            session_id,
            risk_score,
        )
        return True

    # High or Critical severity
    if severity in {"HIGH", "CRITICAL"}:
        logger.info(
            "Sending Telegram alert for %s severity session %s",
            severity,
            session_id,
        )
        return True

    # Alert-worthy tactic
    if tactic in ALERT_WORTHY_TACTICS:
        logger.info(
            "Sending Telegram alert for tactic %s in session %s",
            tactic,
            session_id,
        )
        return True

    # Suspicious keywords in any command
    for cmd in commands:
        cmd_lower = cmd.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in cmd_lower:
                logger.info(
                    "Sending Telegram alert for suspicious keyword '%s' in session %s",
                    keyword,
                    session_id,
                )
                return True

    # ── NOISE checks: suppress if no commands and duration is short ──

    # Are all events low-value?
    all_low_value = all(et in LOW_VALUE_EVENT_TYPES for et in event_types) if event_types else True

    if all_low_value and duration < NOISE_MAX_DURATION_SECONDS:
        logger.info(
            "Skipping Telegram alert for noise session %s (duration=%ds, no commands)",
            session_id,
            duration,
        )
        return False

    # If duration is short and no commands, it's likely a bot
    if command_count == 0 and duration < NOISE_MAX_DURATION_SECONDS:
        logger.info(
            "Skipping Telegram alert for noise session %s (duration=%ds, no commands)",
            session_id,
            duration,
        )
        return False

    # Default: send alert for anything that passes severity/tactic threshold above,
    # or for sessions that don't fit the noise profile
    logger.info(
        "Sending Telegram alert for session %s (risk=%d, severity=%s, tactic=%s)",
        session_id,
        risk_score,
        severity,
        tactic,
    )
    return True


class AnalysisService:
    def __init__(
        self,
        llm_agent: LLMAgent | None = None,
        notifier: TelegramNotifier | None = None,
        pdf_exporter: PDFExporter | None = None,
        ip_enrichment: IPEnrichmentService | None = None,
        output_dir: str = "/app/reports",
        llm_max_concurrent: int = 3,
    ) -> None:
        self.llm_agent = llm_agent or LLMAgent()
        self.notifier = notifier or TelegramNotifier()
        self.pdf_exporter = pdf_exporter or PDFExporter(output_dir)
        self.ip_enrichment = ip_enrichment or IPEnrichmentService()
        self._llm_semaphore = asyncio.Semaphore(llm_max_concurrent)

    async def analyze_and_report(
        self,
        session: Session,
        events: list[Any],
        intel: IPIntel | None,
        db: DBSession,
    ) -> ThreatReport:
        """Full analysis pipeline: enrich IP, generate LLM report, save, PDF, notify."""
        session_id = session.session_id

        if not intel:
            try:
                enriched = await self.ip_enrichment.enrich(session.attacker_ip)
            except Exception as exc:
                logger.warning("IP enrichment failed for %s: %s", session.attacker_ip, exc)
                enriched = {"ip": session.attacker_ip}
            intel = self._upsert_ip_intel(db, enriched)
            db.commit()

        async with self._llm_semaphore:
            report_payload = await self.llm_agent.analyze_session(
                self.model_to_dict(session),
                [self.model_to_dict(event) for event in events],
                self.model_to_dict(intel) if intel else None,
            )
        report_payload = self._merge_ioc(report_payload, session, intel)
        severity = self._resolve_severity(report_payload.get("severity"), session.severity)

        report = ThreatReport(
            session_id=session_id,
            attack_type=report_payload.get("attack_type"),
            severity=severity,
            mitre_techniques=report_payload.get("mitre_techniques", []),
            kill_chain_phase=report_payload.get("kill_chain_phase"),
            attacker_goal=report_payload.get("attacker_goal"),
            attacker_profile=report_payload.get("attacker_profile"),
            ioc=report_payload.get("ioc", {}),
            recommendation=report_payload.get("recommendation"),
            confidence=report_payload.get("confidence"),
            raw_llm_response=report_payload.get("raw_llm_response"),
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        logger.info(
            "ThreatReport saved for session %s: attack_type=%s severity=%s confidence=%s",
            session_id,
            report.attack_type,
            report.severity,
            report.confidence,
        )

        try:
            path = await self._export_pdf(
                self.model_to_dict(report),
                self.model_to_dict(session),
                [self.model_to_dict(event) for event in events],
            )
            report.pdf_path = path
            db.commit()
            db.refresh(report)
        except Exception as exc:
            logger.warning("PDF export failed for session %s: %s", session_id, exc)

        if report.severity in AUTO_NOTIFY_SEVERITIES:
            if should_send_telegram_alert(session, events):
                payload = {**report_payload, "session_id": session_id, "severity": report.severity}
                try:
                    sent = await self.notifier.send_attack_alert(payload)
                except Exception as exc:
                    logger.warning("Telegram notify failed for session %s: %s", session_id, exc)
                    sent = False
                report.notification_sent = sent
                db.commit()
            else:
                logger.info("Suppressed Telegram alert for noise session %s", session_id)
                report.notification_sent = False
                db.commit()

        return report

    def _upsert_ip_intel(self, db: DBSession, data: dict[str, Any]) -> IPIntel:
        payload = normalize_enrichment_payload(data["ip"], data)
        return upsert_ip_intel(db, payload)

    def _merge_ioc(self, report_payload: dict[str, Any], session: Session, intel: IPIntel | None) -> dict[str, Any]:
        ioc = dict(report_payload.get("ioc") or {})
        ioc.setdefault("ip", session.attacker_ip)

        if intel:
            if not ioc.get("country") or str(ioc.get("country")).lower() in {"unknown", "n/a"}:
                ioc["country"] = self._intel_value(intel, "country_name")
            if not ioc.get("city") or str(ioc.get("city")).lower() in {"unknown", "n/a"}:
                ioc["city"] = self._intel_value(intel, "city")
            if not ioc.get("asn"):
                ioc["asn"] = self._intel_value(intel, "asn")
            if not ioc.get("org"):
                ioc["org"] = self._intel_value(intel, "org_name")
            if not ioc.get("country_code"):
                ioc["country_code"] = self._intel_value(intel, "country_code")
            abuse_score = self._intel_value(intel, "abuse_confidence_score")
            if ioc.get("abuse_score") in {None, "unknown", "n/a"} and abuse_score is not None:
                ioc["abuse_score"] = abuse_score

        report_payload["ioc"] = ioc
        return report_payload

    async def _export_pdf(self, report: dict[str, Any], session: dict[str, Any], events: list[dict[str, Any]]) -> str:
        if inspect.iscoroutinefunction(self.pdf_exporter.export):
            return await self.pdf_exporter.export(report, session, events)
        return await asyncio.to_thread(self.pdf_exporter.export, report, session, events)

    def _intel_value(self, intel: Any, field: str) -> Any:
        if isinstance(intel, dict):
            return intel.get(field)
        return getattr(intel, field, None)

    def _resolve_severity(self, report_severity: str | None, session_severity: str | None) -> str:
        rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        report_value = (report_severity or "").upper()
        session_value = (session_severity or "").upper()
        resolved = report_value if rank.get(report_value, -1) >= rank.get(session_value, -1) else session_value
        return resolved if resolved in rank else "LOW"

    def model_to_dict(self, model: Any) -> dict[str, Any]:
        if isinstance(model, dict):
            return model
        return {column.name: getattr(model, column.name) for column in model.__table__.columns}
