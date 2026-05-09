import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Vulnerability, Severity

_DB_PATH = Path(".scan_cache.db")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scan_results (
    file_hash        TEXT PRIMARY KEY,
    file_path        TEXT NOT NULL,
    language         TEXT NOT NULL,
    scanned_at       TEXT NOT NULL,
    vulnerabilities  TEXT NOT NULL,
    duration_ms      REAL NOT NULL
)
"""


class ScanCache:
    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = db_path
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(_CREATE_TABLE)
            conn.commit()

    def get(self, file_hash: str) -> Optional[list[Vulnerability]]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT vulnerabilities FROM scan_results WHERE file_hash = ?",
                (file_hash,),
            ).fetchone()
        if row is None:
            return None
        raw = json.loads(row[0])
        return [
            Vulnerability(
                severity=Severity(v["severity"]),
                type=v["type"],
                description=v["description"],
                impact=v["impact"],
                fix=v["fix"],
                line_number=v.get("line_number"),
                owasp=v.get("owasp"),
                confidence=v.get("confidence", 1.0),
                source=v.get("source", "llm"),
            )
            for v in raw
        ]

    def put(
        self,
        file_hash: str,
        file_path: str,
        language: str,
        vulnerabilities: list[Vulnerability],
        duration_ms: float,
    ) -> None:
        payload = json.dumps([v.model_dump() for v in vulnerabilities], default=str)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_results
                   (file_hash, file_path, language, scanned_at, vulnerabilities, duration_ms)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (file_hash, file_path, language, datetime.utcnow().isoformat(), payload, duration_ms),
            )
            conn.commit()

    def clear(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            conn.execute("DELETE FROM scan_results")
            conn.commit()
        return count

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0]
            oldest = conn.execute("SELECT MIN(scanned_at) FROM scan_results").fetchone()[0]
            newest = conn.execute("SELECT MAX(scanned_at) FROM scan_results").fetchone()[0]
        return {"cached_files": count, "oldest": oldest, "newest": newest}
