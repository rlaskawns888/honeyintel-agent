"""
Cowrie JSON 로그 적재기.

1) 로그 파일을 읽어 raw_events에 INSERT (원문 라인 sha256으로 중복 무시)
2) 이번에 들어온 세션들을 raw_events 기준으로 다시 집계해 sessions에 UPSERT

같은 파일을 여러 번 적재해도 결과가 같다(멱등).

사용:
    python scripts/ingest.py data/dummy/cowrie.json --source dummy
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import psycopg
from dotenv import load_dotenv
from psycopg.types.json import Jsonb

DUMMY_SENSOR = "honeyintel-dummy"
BATCH = 1000

INSERT_RAW = """
INSERT INTO raw_events (dedup_key, eventid, session_id, ts, src_ip, sensor, source, payload)
VALUES (%s, %s, %s, %s::timestamptz, %s::inet, %s, %s, %s)
ON CONFLICT (dedup_key) DO NOTHING
"""

# raw_events → sessions 집계. 세션 전체를 다시 계산하므로 몇 번 돌려도 같은 결과
UPSERT_SESSIONS = """
INSERT INTO sessions (
    session_id, src_ip, src_port, dst_port, protocol, client_version, hassh,
    started_at, ended_at, duration_sec,
    login_attempts, login_success, commands_count, downloads_count, source
)
SELECT
    session_id,
    (array_agg(src_ip ORDER BY ts))[1],
    max((payload->>'src_port')::int),
    max((payload->>'dst_port')::int),
    max(payload->>'protocol')           FILTER (WHERE eventid = 'cowrie.session.connect'),
    max(payload->>'version')            FILTER (WHERE eventid = 'cowrie.client.version'),
    max(payload->>'hassh')              FILTER (WHERE eventid = 'cowrie.client.kex'),
    min(ts),
    max(ts)                             FILTER (WHERE eventid = 'cowrie.session.closed'),
    max((payload->>'duration')::numeric) FILTER (WHERE eventid = 'cowrie.session.closed'),
    count(*) FILTER (WHERE eventid IN ('cowrie.login.failed', 'cowrie.login.success')),
    bool_or(eventid = 'cowrie.login.success'),
    count(*) FILTER (WHERE eventid = 'cowrie.command.input'),
    count(*) FILTER (WHERE eventid = 'cowrie.session.file_download'),
    min(source)
FROM raw_events
WHERE session_id = ANY(%s)
GROUP BY session_id
ON CONFLICT (session_id) DO UPDATE SET
    src_port        = EXCLUDED.src_port,
    dst_port        = EXCLUDED.dst_port,
    protocol        = EXCLUDED.protocol,
    client_version  = EXCLUDED.client_version,
    hassh           = EXCLUDED.hassh,
    started_at      = EXCLUDED.started_at,
    ended_at        = EXCLUDED.ended_at,
    duration_sec    = EXCLUDED.duration_sec,
    login_attempts  = EXCLUDED.login_attempts,
    login_success   = EXCLUDED.login_success,
    commands_count  = EXCLUDED.commands_count,
    downloads_count = EXCLUDED.downloads_count,
    updated_at      = now()
"""


def parse(path: Path, source: str):
    """(rows, session_ids, skipped) 반환. 깨진 줄은 건너뛰고 개수만 센다."""
    rows, sids, skipped = [], set(), 0
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
                eventid, sid, ts, ip = e["eventid"], e["session"], e["timestamp"], e["src_ip"]
            except (json.JSONDecodeError, KeyError) as ex:
                skipped += 1
                print(f"skip line {lineno}: {ex}", file=sys.stderr)
                continue

            # 안전 수칙: 더미가 실데이터(cowrie)로 섞여 들어가 외부로 나가는 것 차단
            if source == "cowrie" and e.get("sensor") == DUMMY_SENSOR:
                sys.exit(f"line {lineno}: dummy sensor data cannot be loaded as source=cowrie")

            dedup = hashlib.sha256(line.encode("utf-8")).hexdigest()
            rows.append((dedup, eventid, sid, ts, ip, e.get("sensor"), source, Jsonb(e)))
            sids.add(sid)
    return rows, sids, skipped


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--source", required=True, choices=["dummy", "cowrie"])
    args = ap.parse_args()

    load_dotenv()
    # .env의 SQLAlchemy 형식(postgresql+psycopg://)을 psycopg용으로 변환
    dsn = os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://")

    rows, sids, skipped = parse(args.path, args.source)

    with psycopg.connect(dsn) as conn:  # 블록 종료 시 commit, 예외 시 rollback
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM raw_events")
            before = cur.fetchone()[0]
            for i in range(0, len(rows), BATCH):
                cur.executemany(INSERT_RAW, rows[i:i + BATCH])
            cur.execute("SELECT count(*) FROM raw_events")
            inserted = cur.fetchone()[0] - before

            cur.execute(UPSERT_SESSIONS, (list(sids),))
            upserted = cur.rowcount

    print(f"read={len(rows)} inserted={inserted} duplicates={len(rows) - inserted} "
          f"skipped={skipped} sessions_upserted={upserted}")


if __name__ == "__main__":
    main()