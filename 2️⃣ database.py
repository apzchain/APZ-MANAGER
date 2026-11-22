import sqlite3
import json
import os
from datetime import datetime


class Database:
    def __init__(self, path=None):
        self.path = path or os.environ.get(
            "APZ_DB_PATH",
            os.path.expanduser("~/apz-reports/apz.db"),
        )
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT NOT NULL,
                file_path TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                confidence INTEGER,
                analyzed_at TEXT,
                report_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sha ON analyses(sha256);

            CREATE TABLE IF NOT EXISTS reputations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256 TEXT NOT NULL,
                source TEXT NOT NULL,
                verdict TEXT,
                score INTEGER,
                raw_json TEXT,
                checked_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_rep_sha ON reputations(sha256);

            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL UNIQUE,
                first_seen TEXT,
                last_seen TEXT,
                source TEXT,
                malicious INTEGER DEFAULT 1
            );
            """)

    def save_analysis(self, report):
        with self._conn() as c:
            c.execute(
                """INSERT INTO analyses
                   (sha256, file_path, risk_score, risk_level, confidence, analyzed_at, report_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.get("sha256"),
                    report.get("file"),
                    report.get("risk_score"),
                    report.get("risk_level"),
                    report.get("confidence"),
                    report.get("analyzed_at", datetime.utcnow().isoformat()),
                    json.dumps(report, ensure_ascii=False),
                ),
            )

    def get_summary(self, sha256):
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM analyses WHERE sha256 = ? ORDER BY id DESC LIMIT 1",
                (sha256,),
            ).fetchone()
        if not row:
            return None
        return {
            "sha256": row["sha256"],
            "file_path": row["file_path"],
            "risk_score": row["risk_score"],
            "risk_level": row["risk_level"],
            "confidence": row["confidence"],
            "analyzed_at": row["analyzed_at"],
        }

    def get_stats(self):
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            by_level = dict(c.execute(
                "SELECT risk_level, COUNT(*) FROM analyses GROUP BY risk_level"
            ).fetchall())
            by_day = [dict(r) for r in c.execute(
                """SELECT substr(analyzed_at, 1, 10) AS day, COUNT(*) as count
                   FROM analyses GROUP BY day ORDER BY day DESC LIMIT 30"""
            ).fetchall()]
        return {"total": total, "by_level": by_level, "recent_days": by_day}

    def save_reputation(self, sha256, source, verdict, score, raw):
        with self._conn() as c:
            c.execute(
                """INSERT INTO reputations
                   (sha256, source, verdict, score, raw_json, checked_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (sha256, source, verdict, score,
                 json.dumps(raw), datetime.utcnow().isoformat()),
            )

    def save_ioc(self, ioc_type, value, source="analysis"):
        now = datetime.utcnow().isoformat()
        with self._conn() as c:
            c.execute(
                """INSERT INTO iocs (type, value, first_seen, last_seen, source)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(value) DO UPDATE SET last_seen=excluded.last_seen""",
                (ioc_type, value, now, now, source),
            )

    def is_known_ioc(self, value):
        with self._conn() as c:
            row = c.execute(
                "SELECT malicious FROM iocs WHERE value = ?", (value,)
            ).fetchone()
        return bool(row and row["malicious"])