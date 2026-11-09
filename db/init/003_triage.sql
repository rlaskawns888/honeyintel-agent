-- triage: 분류해서 처리 우선순위를 정하는 것

CREATE TABLE IF NOT EXISTS triage_results (
    id                  BIGSERIAL PRIMARY KEY,                          -- 결과 행 번호 (자동 증가)
    session_id          TEXT        NOT NULL REFERENCES sessions(session_id), -- 어떤 세션을 분류했는지 (sessions 테이블 참조)
    source              TEXT        NOT NULL CHECK (source IN ('dummy','cowrie')), -- 데이터 출처: 더미 / 실제 허니팟. 피드 공개는 cowrie만
    model               TEXT        NOT NULL,                           -- 분류에 쓴 LLM 이름 (예: gemini-3.1-flash-lite)
    prompt_version      TEXT        NOT NULL,                           -- 프롬프트 버전 (예: v1). 프롬프트 바꿀 때마다 올림
    category            TEXT        NOT NULL CHECK (category IN ('scan','bruteforce','post_exploit','unknown')), -- 분류 결과: 스캔 / 무차별대입 / 침입후행위 / 판단불가
    confidence          REAL        NOT NULL CHECK (confidence BETWEEN 0 AND 1), -- LLM이 적은 확신도 0~1. 낮으면 사람 검토로
    needs_investigation BOOLEAN     NOT NULL,                           -- 조사 Agent(IP·해시 조회)로 넘길지 여부
    result              JSONB       NOT NULL,                           -- LLM 응답 전체 원본 (요약, 근거, URL·해시·명령 등)
    trace_id            TEXT,                                           -- Langfuse 트레이스 ID. 이 값으로 당시 프롬프트·응답 추적
    input_tokens        INT,                                            -- LLM에 보낸 토큰 수 (비용 계산용)
    output_tokens       INT,                                            -- LLM이 응답한 토큰 수 (비용 계산용)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),             -- 분류한 시각
    UNIQUE (session_id, model, prompt_version)                          -- 같은 세션·모델·프롬프트 조합은 1번만 저장 (재실행해도 중복 안 생김)
);

CREATE INDEX IF NOT EXISTS idx_triage_category ON triage_results(category); -- 카테고리별 조회 빠르게 (예: post_exploit만 보기)
CREATE INDEX IF NOT EXISTS idx_triage_source   ON triage_results(source);   -- 출처별 조회 빠르게 (예: cowrie만 보기)