"""SQLite scan history. Summaries are always recomputed server-side from stored results."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """CREATE TABLE IF NOT EXISTS scans(
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, host TEXT, os_family TEXT, distro TEXT,
 version TEXT, source TEXT NOT NULL, summary TEXT NOT NULL, results TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_target ON scans(host, os_family, id);"""
COLS = "id, ts, host, os_family, distro, version, source, summary"


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as c:
            c.executescript(SCHEMA)

    def _rows(self, sql: str, args: tuple = ()) -> list[tuple]:
        with closing(sqlite3.connect(self.path)) as c:
            return c.execute(sql, args).fetchall()

    @staticmethod
    def _meta(r: tuple) -> dict:
        return {"id": r[0], "ts": r[1], "host": r[2], "os_family": r[3], "distro": r[4],
                "version": r[5], "source": r[6], "summary": json.loads(r[7])}

    def save(self, system: dict, summary: dict, results: list[dict], source: str) -> int:
        with closing(sqlite3.connect(self.path)) as c:
            cur = c.execute(
                "INSERT INTO scans(ts,host,os_family,distro,version,source,summary,results) VALUES(?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), system.get("hostname"), system.get("os_family"),
                 system.get("distro"), system.get("version"), source, json.dumps(summary), json.dumps(results)))
            c.commit()
            return int(cur.lastrowid)

    def latest_per_target(self) -> list[dict]:
        rows = self._rows(f"SELECT {COLS} FROM scans WHERE id IN (SELECT MAX(id) FROM scans GROUP BY host, os_family) ORDER BY ts DESC")
        return [self._meta(r) for r in rows]

    def get(self, scan_id: int) -> dict | None:
        rows = self._rows(f"SELECT {COLS}, results FROM scans WHERE id=?", (scan_id,))
        if not rows:
            return None
        m = self._meta(rows[0][:8])
        m["results"] = json.loads(rows[0][8])
        return m

    def history(self, host: str | None, os_family: str | None, limit: int = 30) -> list[dict]:
        rows = self._rows("SELECT id, ts, summary FROM scans WHERE host IS ? AND os_family IS ? ORDER BY id DESC LIMIT ?", (host, os_family, limit))
        return [{"id": r[0], "ts": r[1], "score_percent": json.loads(r[2])["score_percent"]} for r in reversed(rows)]
