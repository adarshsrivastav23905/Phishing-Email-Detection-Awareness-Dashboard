import json
import sqlite3
from datetime import datetime, timezone

from .config import HISTORY_DB_PATH


def init_db():
    with sqlite3.connect(HISTORY_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                classification TEXT,
                risk_score INTEGER,
                findings TEXT,
                recommendations TEXT,
                features TEXT
            )
            """
        )
        conn.commit()


def save_analysis(report):
    with sqlite3.connect(HISTORY_DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO analysis_history (timestamp, sender, subject, classification, risk_score, findings, recommendations, features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report.get("created_at") or datetime.now(timezone.utc).isoformat(),
                report.get("sender", ""),
                report.get("subject", ""),
                report.get("classification", "SAFE"),
                report.get("risk_score", 0),
                json.dumps(report.get("findings", [])),
                json.dumps(report.get("recommendations", [])),
                json.dumps(report.get("features", {})),
            ),
        )
        conn.commit()


def get_history(limit=10):
    with sqlite3.connect(HISTORY_DB_PATH) as conn:
        rows = conn.execute(
            """
            SELECT timestamp, sender, subject, classification, risk_score
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "timestamp": row[0],
            "sender": row[1],
            "subject": row[2],
            "classification": row[3],
            "risk_score": row[4],
        }
        for row in rows
    ]
