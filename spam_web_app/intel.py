"""Threat intelligence (dynamic keyword DB) + inbox-style categorization."""
from __future__ import annotations

import json
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
THREAT_PATH = APP_DIR / "threat_keywords.json"


def _default_db() -> dict:
    return {"phishing": [], "scam": [], "promotion": [], "social": []}


def load_threat_db() -> dict:
    if THREAT_PATH.exists():
        try:
            data = json.loads(THREAT_PATH.read_text(encoding="utf-8"))
            for k in ("phishing", "scam", "promotion", "social"):
                data.setdefault(k, [])
            return data
        except (json.JSONDecodeError, OSError):
            pass
    return _default_db()


def _find_hits(text: str, keywords: list) -> list:
    if not text or not keywords:
        return []
    lower = text.lower()
    found = []
    for kw in keywords:
        if not kw:
            continue
        if kw.lower() in lower:
            found.append(kw)
    return found


def analyze_threats(raw_text: str, db: dict | None = None) -> tuple[str, dict[str, list]]:
    db = db or load_threat_db()
    hits = {
        "phishing": _find_hits(raw_text, db.get("phishing", [])),
        "scam": _find_hits(raw_text, db.get("scam", [])),
        "promotion": _find_hits(raw_text, db.get("promotion", [])),
    }
    if hits["phishing"]:
        threat_type = "Phishing"
    elif hits["scam"]:
        threat_type = "Scam"
    elif hits["promotion"]:
        threat_type = "Promotion"
    else:
        threat_type = "Clean"
    return threat_type, hits


def compute_risk_score(spam_probability: float, threat_hits: dict[str, list]) -> float:
    r = float(spam_probability)
    if threat_hits.get("phishing"):
        r += 28
    if threat_hits.get("scam"):
        r += 18
    if threat_hits.get("promotion"):
        r += 10
    return round(min(100.0, r), 1)


def risk_level(score: float) -> str:
    if score < 36:
        return "Low"
    if score < 68:
        return "Medium"
    return "High"


def classify_category(
    is_spam: bool,
    raw_text: str,
    threat_type: str,
    promotion_hits: list,
) -> str:
    if is_spam:
        return "Spam"
    t = (raw_text or "").lower()
    social_kw = load_threat_db().get("social", [])
    for s in social_kw:
        if s.lower() in t:
            return "Social"
    if threat_type == "Promotion" or len(promotion_hits) >= 2:
        return "Promotions"
    if promotion_hits or "unsubscribe" in t or "% off" in t or "sale" in t:
        return "Promotions"
    return "Important"


def threat_explanation(threat_type: str, hits: dict[str, list]) -> list[str]:
    lines = []
    if threat_type == "Clean":
        lines.append("No high-risk threat keywords from the intelligence database matched this message.")
        return lines
    lines.append(
        f"Threat intelligence classifies this message as {threat_type} based on keyword matches."
    )
    if hits.get("phishing"):
        lines.append("Phishing indicators: " + ", ".join(hits["phishing"][:6]) + ("…" if len(hits["phishing"]) > 6 else "") + ".")
    if hits.get("scam"):
        lines.append("Scam indicators: " + ", ".join(hits["scam"][:6]) + ("…" if len(hits["scam"]) > 6 else "") + ".")
    if hits.get("promotion") and threat_type == "Promotion":
        lines.append("Promotional indicators: " + ", ".join(hits["promotion"][:6]) + ("…" if len(hits["promotion"]) > 6 else "") + ".")
    return lines


def reload_threat_db() -> dict:
    """Call after admin edits JSON (future); for now re-reads file."""
    return load_threat_db()
