from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class EventOut(BaseModel):
    id: UUID
    session_id: str | None
    event_type: str | None
    event_data: dict[str, Any] | None
    raw_command: str | None
    mitre_technique: str | None
    mitre_tactic: str | None
    timestamp: datetime | None

    class Config:
        from_attributes = True


class SessionOut(BaseModel):
    id: UUID
    session_id: str
    attacker_ip: str
    start_time: datetime | None
    end_time: datetime | None
    duration_seconds: int | None
    login_attempts: int
    successful_login: bool
    current_tactic: str | None
    tactic_history: list[dict[str, Any]] | None
    risk_score: int
    adaptation_applied: str | None
    severity: str | None

    class Config:
        from_attributes = True


class ThreatReportOut(BaseModel):
    id: UUID
    session_id: str | None
    attack_type: str | None
    severity: str | None
    mitre_techniques: list[Any] | None
    kill_chain_phase: str | None
    attacker_goal: str | None
    attacker_profile: str | None
    ioc: dict[str, Any] | None
    recommendation: str | None
    confidence: float | None
    pdf_path: str | None
    notification_sent: bool
    created_at: datetime | None

    class Config:
        from_attributes = True


class StatsOut(BaseModel):
    total_attacks: int
    top_ips: list[dict[str, Any]]
    top_countries: list[dict[str, Any]]
    top_tactics: list[dict[str, Any]]
    top_passwords: list[dict[str, Any]]


class MapAttackPoint(BaseModel):
    source_ip: str
    country: str
    city: str
    lat: float | None = None
    lon: float | None = None
    severity: str | None = "LOW"
    risk_score: int = 0
    timestamp: datetime | None = None


class MapHoneypotNode(BaseModel):
    lat: float
    lon: float
    city: str
    country: str


class MapResponse(BaseModel):
    attacks: list[MapAttackPoint]
    honeypot: MapHoneypotNode
