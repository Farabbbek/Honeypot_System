from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import expression

from database import Base


class Session(Base):
    __tablename__ = "sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    attacker_ip = Column(String(45), nullable=False, index=True)
    start_time = Column(DateTime, server_default=func.now())
    end_time = Column(DateTime)
    duration_seconds = Column(Integer)
    login_attempts = Column(Integer, default=0)
    successful_login = Column(Boolean, default=False)
    current_tactic = Column(String(64), index=True)
    tactic_history = Column(JSONB, default=list)
    risk_score = Column(Integer, default=0)
    adaptation_applied = Column(String(64))
    severity = Column(String(16), default="LOW", index=True)
    created_at = Column(DateTime, server_default=func.now())

    events = relationship("Event", back_populates="session", cascade="all, delete-orphan")
    reports = relationship("ThreatReport", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
    )


class Event(Base):
    __tablename__ = "events"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    session_id = Column(
        String(64),
        ForeignKey("sessions.session_id", ondelete="CASCADE"),
        index=True,
    )
    event_type = Column(String(64))
    event_data = Column(JSONB, default=dict)
    raw_command = Column(Text)
    mitre_technique = Column(String(16))
    mitre_tactic = Column(String(64), index=True)
    timestamp = Column(DateTime, server_default=func.now(), index=True)
    created_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="events")


class IPIntel(Base):
    __tablename__ = "ip_intel"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    ip = Column(String(45), unique=True, nullable=False, index=True)
    country_code = Column(String(4), index=True)
    country_name = Column(String(128))
    city = Column(String(128))
    latitude = Column(Float)
    longitude = Column(Float)
    asn = Column(String(64))
    org_name = Column(String(256))
    abuse_confidence_score = Column(Integer)
    total_reports = Column(Integer, default=0)
    last_reported_at = Column(DateTime)
    is_tor = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    enriched_at = Column(DateTime, server_default=func.now())


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    session_id = Column(
        String(64),
        ForeignKey("sessions.session_id", ondelete="CASCADE"),
        index=True,
    )
    attack_type = Column(String(256))
    severity = Column(String(16), index=True)
    mitre_techniques = Column(JSONB, default=list)
    kill_chain_phase = Column(String(64))
    attacker_goal = Column(Text)
    attacker_profile = Column(Text)
    ioc = Column(JSONB, default=dict)
    recommendation = Column(Text)
    confidence = Column(Float)
    raw_llm_response = Column(Text)
    pdf_path = Column(String(256))
    notification_sent = Column(Boolean, server_default=expression.false())
    created_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="reports")


class PasswordStat(Base):
    __tablename__ = "password_stats"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())
    password = Column(String(256), unique=True, nullable=False)
    attempt_count = Column(Integer, default=1)
    last_seen = Column(DateTime, server_default=func.now())
