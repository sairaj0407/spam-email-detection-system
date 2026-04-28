"""SQLite schema upgrades for new columns."""
from __future__ import annotations

from sqlalchemy import inspect, text

from models import db


def migrate_sqlite() -> None:
    engine = db.engine
    if engine.dialect.name != "sqlite":
        return

    insp = inspect(engine)

    if insp.has_table("users"):
        cols = {c["name"] for c in insp.get_columns("users")}
        with engine.begin() as conn:
            if "role" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(16)"))
                conn.execute(text("UPDATE users SET role = 'user' WHERE role IS NULL OR role = ''"))
            if "is_banned" not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0"))
                conn.execute(text("UPDATE users SET is_banned = 0 WHERE is_banned IS NULL"))

    if insp.has_table("emails"):
        cols = {c["name"] for c in insp.get_columns("emails")}
        with engine.begin() as conn:
            if "category" not in cols:
                conn.execute(text("ALTER TABLE emails ADD COLUMN category VARCHAR(32)"))
                conn.execute(text("UPDATE emails SET category = 'Important' WHERE category IS NULL"))
            if "threat_type" not in cols:
                conn.execute(text("ALTER TABLE emails ADD COLUMN threat_type VARCHAR(32)"))
                conn.execute(text("UPDATE emails SET threat_type = 'Clean' WHERE threat_type IS NULL"))
            if "risk_score" not in cols:
                conn.execute(text("ALTER TABLE emails ADD COLUMN risk_score FLOAT"))
                conn.execute(
                    text("UPDATE emails SET risk_score = confidence WHERE risk_score IS NULL")
                )
            if "risk_level" not in cols:
                conn.execute(text("ALTER TABLE emails ADD COLUMN risk_level VARCHAR(16)"))
                conn.execute(text("UPDATE emails SET risk_level = 'Medium' WHERE risk_level IS NULL"))
