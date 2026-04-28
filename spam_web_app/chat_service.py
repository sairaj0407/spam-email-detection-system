"""Rule-based assistant replies + optional use of last analysis context."""
from __future__ import annotations


def _kw_list(ctx: dict, key: str, limit: int = 6) -> str:
    items = ctx.get(key) or []
    if isinstance(items, list) and items and isinstance(items[0], dict):
        terms = [x.get("term", "") for x in items[:limit] if x.get("term")]
    elif isinstance(items, list):
        terms = [str(x) for x in items[:limit]]
    else:
        terms = []
    return ", ".join(terms) if terms else "none highlighted"


def build_reply(message: str, context: dict | None) -> str:
    m = (message or "").strip().lower()
    ctx = context or {}

    if not m:
        return "Ask me anything about spam, phishing, or your last analysis."

    # Use last email analysis when relevant
    if ctx.get("has_analysis"):
        if any(
            w in m
            for w in (
                "why",
                "spam",
                "explain",
                "result",
                "this email",
                "marked",
                "classified",
                "prediction",
            )
        ):
            is_spam = ctx.get("is_spam")
            conf = ctx.get("confidence")
            risk = ctx.get("risk_score")
            threat = ctx.get("threat_type", "Clean")
            cat = ctx.get("category", "—")
            terms = _kw_list(ctx, "top_keywords")
            if is_spam is True:
                return (
                    f"This email was classified as spam with about {conf}% model confidence and a risk score of {risk}/100. "
                    f"Threat intel labeled it as {threat} (inbox category: {cat}). "
                    f"Strongest spam-associated terms in the model include: {terms}. "
                    "Combine that with sender verification before clicking links."
                )
            if is_spam is False:
                return (
                    f"The model considers this email legitimate (~{conf}% confidence), risk score {risk}/100. "
                    f"Threat type: {threat}, category: {cat}. "
                    f"Some risky-looking words can still appear: {terms}. When in doubt, confirm with the sender out-of-band."
                )

    if "phishing" in m:
        return (
            "Phishing is when someone tricks you into sharing passwords, OTPs, or money by pretending to be a trusted party. "
            "Watch for urgent tone, mismatched sender addresses, and links that don’t match the real company. "
            "Never enter credentials from an email link—open the site yourself in the browser."
        )

    if "spam" in m and "why" not in m and "stay" not in m:
        return (
            "Spam is unwanted bulk email—ads, scams, or malware bait. Our model scores text patterns (words like “urgent”, “lottery”, “click now”) "
            "plus threat keywords. Use the analyzer before trusting a message, and keep your inbox filters on."
        )

    if "stay safe" in m or "protect" in m or "avoid" in m:
        return (
            "Stay safe: don’t click unknown links; verify sender via a second channel; use unique strong passwords and 2FA; "
            "never share OTPs; treat “too good to be true” offers as red flags; keep software updated."
        )

    if "hello" in m or m == "hi" or m.startswith("hey"):
        return "Hi! I’m SpamShield Assistant. Ask about spam, phishing, your last scan, or how to stay safe online."

    if "help" in m:
        return (
            "Try: “Why is this email spam?” (after an analysis), “What is phishing?”, or “How to stay safe from spam?” "
            "I use your last analysis when you ask about the current result."
        )

    return (
        "I’m a built-in assistant with curated answers about spam, phishing, and safe habits. "
        "Run an email analysis, then ask “Why is this spam?” for a tailored explanation. "
        "You can also ask what phishing is or how to avoid scams."
    )
