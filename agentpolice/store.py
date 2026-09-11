"""SQLite persistence for canaries and their hits.

Deliberately holds no credentials, no prompts and no audit bodies: only the
canary tokens agent-police issued and the fact that something touched them.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from .canary import Canary, CanaryHit, CanaryStore

SCHEMA = """
CREATE TABLE IF NOT EXISTS canaries (
    token       TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    placement   TEXT NOT NULL,
    observable  INTEGER NOT NULL,
    created_at  REAL NOT NULL,
    note        TEXT DEFAULT '',
    audit_id    TEXT
);
CREATE TABLE IF NOT EXISTS hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,
    kind        TEXT NOT NULL,
    at          REAL NOT NULL,
    source_ip   TEXT,
    user_agent  TEXT,
    detail      TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS hits_token ON hits(token);
CREATE INDEX IF NOT EXISTS canaries_audit ON canaries(audit_id);
"""


class SqliteCanaryStore(CanaryStore):
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def register(self, canary: Canary, audit_id: str | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO canaries "
                "(token, kind, value, placement, observable, created_at, note, audit_id) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (canary.token, canary.kind, canary.value, canary.placement,
                 int(canary.observable), canary.created_at, canary.note, audit_id),
            )

    def record_hit(self, hit: CanaryHit) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO hits (token, kind, at, source_ip, user_agent, detail) "
                "VALUES (?,?,?,?,?,?)",
                (hit.token, hit.kind, hit.at, hit.source_ip, hit.user_agent, hit.detail),
            )

    def hits(self, tokens: list[str]) -> list[CanaryHit]:
        if not tokens:
            return []
        placeholders = ",".join("?" * len(tokens))
        rows = self._conn().execute(
            f"SELECT * FROM hits WHERE token IN ({placeholders}) ORDER BY at", tokens
        ).fetchall()
        return [CanaryHit(r["token"], r["kind"], r["at"], r["source_ip"],
                          r["user_agent"], r["detail"]) for r in rows]

    def hits_for_audit(self, audit_id: str) -> list[CanaryHit]:
        rows = self._conn().execute(
            "SELECT h.* FROM hits h JOIN canaries c ON c.token = h.token "
            "WHERE c.audit_id = ? ORDER BY h.at", (audit_id,)
        ).fetchall()
        return [CanaryHit(r["token"], r["kind"], r["at"], r["source_ip"],
                          r["user_agent"], r["detail"]) for r in rows]

    def lookup(self, token: str) -> Canary | None:
        row = self._conn().execute(
            "SELECT * FROM canaries WHERE token = ?", (token,)
        ).fetchone()
        if row is None:
            return None
        return Canary(row["token"], row["kind"], row["value"], row["placement"],
                      bool(row["observable"]), row["created_at"], row["note"])

    def tokens_for_audit(self, audit_id: str) -> list[str]:
        rows = self._conn().execute(
            "SELECT token FROM canaries WHERE audit_id = ?", (audit_id,)
        ).fetchall()
        return [r["token"] for r in rows]

    def purge_older_than(self, seconds: float) -> int:
        cutoff = time.time() - seconds
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM canaries WHERE created_at < ?", (cutoff,))
            conn.execute("DELETE FROM hits WHERE at < ?", (cutoff,))
            return cur.rowcount
