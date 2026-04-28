"""Shared email text preprocessing for train and predict."""
import email
import re
from email import policy

from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS

_STOP = frozenset(ENGLISH_STOP_WORDS)


def preprocess(text: str) -> str:
    if not text or not str(text).strip():
        return ""
    t = str(text).lower()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    words = [w for w in t.split() if w and w not in _STOP]
    return " ".join(words)


def _html_to_plain(html: str) -> str:
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html or "")
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def parse_eml(raw_bytes: bytes) -> str:
    """Extract human-readable text from a .eml message (subject + best body)."""
    if not raw_bytes:
        return ""
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    subj = str(msg.get("Subject") or "")
    chunks = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_maintype() == "multipart":
                continue
            if ctype == "text/plain":
                try:
                    raw = part.get_content()
                except Exception:
                    raw = part.get_payload()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                chunks.append(str(raw))
            elif ctype == "text/html" and not chunks:
                try:
                    raw = part.get_content()
                except Exception:
                    raw = part.get_payload()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                plain = _html_to_plain(str(raw))
                if plain:
                    chunks.append(plain)
    else:
        ctype = msg.get_content_type()
        try:
            body = msg.get_content()
        except Exception:
            body = msg.get_payload()
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        body = str(body)
        if ctype == "text/html":
            body = _html_to_plain(body)
        chunks.append(body)

    body = "\n\n".join(c for c in chunks if c)
    return f"Subject: {subj}\n\n{body}".strip()


def extract_upload_text(filename: str, raw_bytes: bytes) -> str:
    """Decode .txt or parse .eml into a single string for analysis."""
    name = (filename or "").lower()
    if name.endswith(".eml"):
        return parse_eml(raw_bytes).strip()
    return raw_bytes.decode("utf-8", errors="replace").strip()


# Keywords that trigger phishing-style alerts (case-insensitive check on raw text)
PHISHING_KEYWORDS = (
    "bank",
    "otp",
    "urgent",
    "verify",
    "password",
    "ssn",
    "wire transfer",
    "account suspended",
    "click here",
    "limited time",
    "inheritance",
    "lottery winner",
    "social security",
)
