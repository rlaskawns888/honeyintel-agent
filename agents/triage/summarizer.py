"""세션 요약 빌더: sessions(집계) + raw_events(원문 일부) → LLM 입력용 요약"""
import json
import os
from collections import Counter

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

load_dotenv()
# DB_URL = os.environ["DATABASE_URL"]  # ingest.py와 같은 .env 변수명으로 맞출 것
DB_URL = os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)

MAX_COMMANDS = 20      # 명령 원문 최대 20개
MAX_CMD_LEN = 200      # 명령 1개당 200자까지
MAX_USERNAMES = 5      # 시도 계정명 상위 5개


def fetch_session(conn, session_id: str) -> dict:
    """sessions 테이블의 집계값 1행 (이미 적재기가 계산해 둔 값)"""
    row = conn.execute("""
        SELECT session_id, src_ip::text, dst_port, protocol, client_version,
               started_at, duration_sec, login_attempts, login_success,
               commands_count, downloads_count, source
        FROM sessions WHERE session_id = %s
    """, (session_id,)).fetchone()
    if row is None:
        raise ValueError(f"세션 없음: {session_id}")
    return row


def fetch_details(conn, session_id: str) -> dict:
    """sessions에 없는 원문 정보만 raw_events.payload에서 추출"""
    rows = conn.execute("""
        SELECT eventid, payload FROM raw_events
        WHERE session_id = %s
          AND eventid IN ('cowrie.login.failed', 'cowrie.login.success',
                          'cowrie.command.input', 'cowrie.session.file_download')
        ORDER BY ts
    """, (session_id,)).fetchall()

    usernames, commands, downloads = Counter(), [], []
    for r in rows:
        p = r["payload"]                                   # Cowrie 원본 JSON (dict)
        if r["eventid"].startswith("cowrie.login."):
            usernames[p.get("username", "")] += 1
        elif r["eventid"] == "cowrie.command.input" and len(commands) < MAX_COMMANDS:
            commands.append(p.get("input", "")[:MAX_CMD_LEN])
        elif r["eventid"] == "cowrie.session.file_download":
            downloads.append({"url": p.get("url"), "sha256": p.get("shasum")})

    return {
        "top_usernames": [u for u, _ in usernames.most_common(MAX_USERNAMES)],
        "commands": commands,
        "downloads": downloads,
    }


def build_summary(conn, session_id: str) -> dict:
    """집계값 + 원문 일부를 합친 요약"""
    s = fetch_session(conn, session_id)
    d = fetch_details(conn, session_id)
    return {
        "session_id": s["session_id"],
        "src_ip": s["src_ip"],
        "dst_port": s["dst_port"],
        "protocol": s["protocol"],
        "client_version": s["client_version"],
        "duration_sec": float(s["duration_sec"]) if s["duration_sec"] is not None else None,
        "login_attempts": s["login_attempts"],
        "login_success": s["login_success"],
        "commands_count": s["commands_count"],
        "downloads_count": s["downloads_count"],
        **d,
    }


def to_llm_input(summary: dict) -> str:
    """JSON 문자열로 감싸 공격자 명령을 '지시'가 아닌 '데이터'로 전달"""
    return json.dumps(summary, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    # 테스트: 성격이 다른 세션 3개를 sessions 집계값으로 골라 요약 출력 (LLM 호출 없음)
    with psycopg.connect(DB_URL, row_factory=dict_row) as conn:
        picks = conn.execute("""
            (SELECT session_id FROM sessions WHERE commands_count > 0 LIMIT 1)          -- post_exploit 후보
            UNION ALL
            (SELECT session_id FROM sessions WHERE login_attempts >= 3
                                               AND commands_count = 0 LIMIT 1)        -- bruteforce 후보
            UNION ALL
            (SELECT session_id FROM sessions WHERE login_attempts = 0 LIMIT 1)        -- scan 후보
        """).fetchall()

        for p in picks:
            print(to_llm_input(build_summary(conn, p["session_id"])))
            print("-" * 60)