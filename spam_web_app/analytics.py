"""Aggregations for dashboards and admin reporting."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import joinedload

from models import EmailRecord, User, db
from text_utils import preprocess


def _day_key_sql():
    return func.strftime("%Y-%m-%d", EmailRecord.created_at)


def user_email_trend(user_id: int, days: int = 14) -> tuple[list[str], list[int]]:
    since = datetime.utcnow() - timedelta(days=days)
    day = _day_key_sql()
    q = (
        db.session.query(day.label("d"), func.count(EmailRecord.id))
        .filter(EmailRecord.user_id == user_id, EmailRecord.created_at >= since)
        .group_by(day)
        .order_by(day)
    )
    labels = []
    counts = []
    for d, c in q.all():
        if d:
            labels.append(d)
            counts.append(int(c))
    return labels, counts


def system_email_trend(days: int = 14) -> tuple[list[str], list[int], list[int]]:
    """Returns labels, spam_counts per day, safe_counts per day."""
    since = datetime.utcnow() - timedelta(days=days)
    day = _day_key_sql()
    q = (
        db.session.query(
            day.label("d"),
            EmailRecord.prediction,
            func.count(EmailRecord.id),
        )
        .filter(EmailRecord.created_at >= since)
        .group_by(day, EmailRecord.prediction)
        .order_by(day)
    )
    by_day: dict[str, dict[str, int]] = {}
    for d, pred, c in q.all():
        if not d:
            continue
        by_day.setdefault(d, {"Spam": 0, "Safe": 0})
        if pred in by_day[d]:
            by_day[d][pred] = int(c)
    labels = sorted(by_day.keys())
    spam_c = [by_day[d]["Spam"] for d in labels]
    safe_c = [by_day[d]["Safe"] for d in labels]
    return labels, spam_c, safe_c


def top_spam_tokens(limit: int = 15, max_emails: int = 1500) -> list[tuple[str, int]]:
    rows = (
        EmailRecord.query.filter(EmailRecord.prediction == "Spam")
        .order_by(EmailRecord.created_at.desc())
        .limit(max_emails)
        .all()
    )
    c: Counter[str] = Counter()
    for r in rows:
        for w in preprocess(r.email_text or "").split():
            if len(w) > 3:
                c[w] += 1
    return c.most_common(limit)


def recent_activity(limit: int = 8) -> list[dict]:
    rows = (
        EmailRecord.query.options(joinedload(EmailRecord.user))
        .order_by(EmailRecord.created_at.desc())
        .limit(limit)
        .all()
    )
    activity = []
    for row in rows:
        user_label = row.user.username if row.user and row.user.username else row.user.email if row.user else "Unknown"
        snippet = " ".join(str(row.email_text or "").split())
        if len(snippet) > 90:
            snippet = snippet[:90].rstrip() + "…"
        activity.append(
            {
                "user": user_label,
                "outcome": row.prediction or "Unknown",
                "category": row.category or "General",
                "risk_level": row.risk_level or "Medium",
                "timestamp": row.created_at.strftime("%Y-%m-%d %H:%M UTC") if row.created_at else "Unknown",
                "snippet": snippet or "No text available.",
            }
        )
    return activity


def active_users_summary(limit: int = 6) -> list[dict]:
    q = (
        db.session.query(
            User.username,
            User.email,
            func.count(EmailRecord.id).label("email_count"),
            func.sum(case([(EmailRecord.prediction == "Spam", 1)], else_=0)).label("spam_count"),
        )
        .join(EmailRecord, EmailRecord.user_id == User.id)
        .group_by(User.id)
        .order_by(func.count(EmailRecord.id).desc())
        .limit(limit)
    )
    users = []
    for row in q.all():
        email_count = int(row.email_count or 0)
        spam_count = int(row.spam_count or 0)
        spam_percent = round(100.0 * spam_count / email_count, 1) if email_count else 0.0
        users.append(
            {
                "user": row.username or row.email or "Unknown",
                "emails": email_count,
                "spam_percent": spam_percent,
            }
        )
    return users


def system_counts() -> dict:
    total_users = User.query.count()
    total_emails = EmailRecord.query.count()
    spam = EmailRecord.query.filter(EmailRecord.prediction == "Spam").count()
    safe = EmailRecord.query.filter(EmailRecord.prediction == "Safe").count()
    return {
        "users": total_users,
        "emails": total_emails,
        "spam": spam,
        "safe": safe,
    }
