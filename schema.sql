CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(64) UNIQUE NOT NULL,
    attacker_ip VARCHAR(45) NOT NULL,
    start_time TIMESTAMP DEFAULT now(),
    end_time TIMESTAMP,
    duration_seconds INTEGER,
    login_attempts INTEGER DEFAULT 0,
    successful_login BOOLEAN DEFAULT FALSE,
    current_tactic VARCHAR(64),
    tactic_history JSONB DEFAULT '[]'::jsonb,
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    adaptation_applied VARCHAR(64),
    severity VARCHAR(16) DEFAULT 'LOW',
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(64) REFERENCES sessions(session_id) ON DELETE CASCADE,
    event_type VARCHAR(64),
    event_data JSONB DEFAULT '{}'::jsonb,
    raw_command TEXT,
    mitre_technique VARCHAR(16),
    mitre_tactic VARCHAR(64),
    timestamp TIMESTAMP DEFAULT now(),
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE ip_intel (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip VARCHAR(45) UNIQUE NOT NULL,
    country_code VARCHAR(4),
    country_name VARCHAR(128),
    city VARCHAR(128),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    asn VARCHAR(64),
    org_name VARCHAR(256),
    abuse_confidence_score INTEGER CHECK (
        abuse_confidence_score IS NULL
        OR (abuse_confidence_score >= 0 AND abuse_confidence_score <= 100)
    ),
    total_reports INTEGER DEFAULT 0,
    last_reported_at TIMESTAMP,
    is_tor BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    enriched_at TIMESTAMP DEFAULT now()
);

CREATE TABLE threat_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(64) REFERENCES sessions(session_id) ON DELETE CASCADE,
    attack_type VARCHAR(256),
    severity VARCHAR(16),
    mitre_techniques JSONB DEFAULT '[]'::jsonb,
    kill_chain_phase VARCHAR(64),
    attacker_goal TEXT,
    attacker_profile TEXT,
    ioc JSONB DEFAULT '{}'::jsonb,
    recommendation TEXT,
    confidence DOUBLE PRECISION CHECK (
        confidence IS NULL
        OR (confidence >= 0.0 AND confidence <= 1.0)
    ),
    raw_llm_response TEXT,
    pdf_path VARCHAR(256),
    notification_sent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE password_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    password VARCHAR(256) UNIQUE NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    last_seen TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_sessions_attacker_ip ON sessions(attacker_ip);
CREATE INDEX idx_sessions_severity ON sessions(severity);
CREATE INDEX idx_sessions_current_tactic ON sessions(current_tactic);
CREATE INDEX idx_events_session_id_timestamp ON events(session_id, timestamp);
CREATE INDEX idx_events_mitre_tactic ON events(mitre_tactic);
CREATE INDEX idx_ip_intel_country_code ON ip_intel(country_code);
CREATE INDEX idx_threat_reports_severity ON threat_reports(severity);
