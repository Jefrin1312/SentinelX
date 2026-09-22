-- ============================================================
-- SentinelX database schema
-- The canonical schema is managed by the backend through the
-- SQLAlchemy ORM (see backend/app/models). This file mirrors the
-- schema for container bootstrap (docker-entrypoint-initdb.d) and
-- as a human-readable reference.
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT       NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'ANALYST' CHECK (role IN ('ADMIN', 'ANALYST')),
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS events (
    id           SERIAL PRIMARY KEY,
    "timestamp"  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_ip    VARCHAR(45),
    destination_ip VARCHAR(45),
    username     VARCHAR(100),
    event_type   VARCHAR(80)  NOT NULL,
    status       VARCHAR(30)  NOT NULL DEFAULT 'UNKNOWN',
    severity     VARCHAR(20)  NOT NULL DEFAULT 'LOW',
    source       VARCHAR(30)  NOT NULL DEFAULT 'UNKNOWN',
    message      TEXT         NOT NULL,
    metadata     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events ("timestamp");
CREATE INDEX IF NOT EXISTS idx_events_source_ip  ON events (source_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity   ON events (severity);
CREATE INDEX IF NOT EXISTS idx_events_username   ON events (username);

CREATE TABLE IF NOT EXISTS detection_rules (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(120) NOT NULL UNIQUE,
    description     TEXT         NOT NULL,
    category        VARCHAR(60)  NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    threshold       INTEGER      NOT NULL DEFAULT 5,
    time_window     INTEGER      NOT NULL DEFAULT 300,
    rule_definition JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    event_id    INTEGER REFERENCES events(id) ON DELETE SET NULL,
    rule_id     INTEGER REFERENCES detection_rules(id) ON DELETE SET NULL,
    alert_type  VARCHAR(80) NOT NULL,
    severity    VARCHAR(20) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    source_ip   VARCHAR(45),
    description TEXT        NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts (source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts (created_at);

CREATE TABLE IF NOT EXISTS investigations (
    id          SERIAL PRIMARY KEY,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED')),
    summary     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id               SERIAL PRIMARY KEY,
    investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id          INTEGER REFERENCES users(id) ON DELETE SET NULL,
    note             TEXT    NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username      VARCHAR(50),
    action        VARCHAR(60) NOT NULL,
    resource_type VARCHAR(40),
    resource_id   VARCHAR(40),
    ip_address    VARCHAR(45),
    "timestamp"   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs ("timestamp");
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_user      ON audit_logs (user_id);

CREATE TABLE IF NOT EXISTS token_blacklist (
    id         SERIAL PRIMARY KEY,
    jti        VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_blacklist_jti    ON token_blacklist (jti);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist (expires_at);