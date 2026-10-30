-- db/init/002_schema.sql
-- Cowrie 원본 이벤트 + 세션 집계

-- 1) 원본 이벤트: Cowrie JSON 1줄 = 1행. 원문은 payload에 보존
CREATE TABLE IF NOT EXISTS raw_events (
    id           BIGSERIAL PRIMARY KEY,
    dedup_key    CHAR(64)    NOT NULL UNIQUE,      -- 원문 JSON 라인 sha256 (재적재 중복 방지)
    eventid      TEXT        NOT NULL,             -- cowrie.login.failed 등
    session_id   TEXT        NOT NULL,             -- Cowrie session
    ts           TIMESTAMPTZ NOT NULL,
    src_ip       INET        NOT NULL,
    sensor       TEXT,
    source       TEXT        NOT NULL CHECK (source IN ('dummy', 'cowrie')),
    payload      JSONB       NOT NULL,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_raw_events_session ON raw_events (session_id, ts);
CREATE INDEX IF NOT EXISTS ix_raw_events_ts      ON raw_events (ts);
CREATE INDEX IF NOT EXISTS ix_raw_events_eventid ON raw_events (eventid);
CREATE INDEX IF NOT EXISTS ix_raw_events_src_ip  ON raw_events (src_ip);

-- 2) 세션: Agent 입력 단위. 적재기가 raw_events로부터 갱신
CREATE TABLE IF NOT EXISTS sessions (
    session_id       TEXT PRIMARY KEY,
    src_ip           INET        NOT NULL,
    src_port         INT,
    dst_port         INT,
    protocol         TEXT,                          -- ssh / telnet
    client_version   TEXT,                          -- SSH 클라이언트 배너
    hassh            TEXT,                          -- SSH 클라이언트 지문
    started_at       TIMESTAMPTZ NOT NULL,
    ended_at         TIMESTAMPTZ,
    duration_sec     NUMERIC(10, 3),
    login_attempts   INT         NOT NULL DEFAULT 0,
    login_success    BOOLEAN     NOT NULL DEFAULT FALSE,
    commands_count   INT         NOT NULL DEFAULT 0,
    downloads_count  INT         NOT NULL DEFAULT 0,
    source           TEXT        NOT NULL CHECK (source IN ('dummy', 'cowrie')),
    analysis_status  TEXT        NOT NULL DEFAULT 'pending'
                     CHECK (analysis_status IN ('pending', 'in_progress', 'done', 'failed')),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_sessions_src_ip  ON sessions (src_ip);
CREATE INDEX IF NOT EXISTS ix_sessions_started ON sessions (started_at);
CREATE INDEX IF NOT EXISTS ix_sessions_pending ON sessions (analysis_status) WHERE analysis_status = 'pending';