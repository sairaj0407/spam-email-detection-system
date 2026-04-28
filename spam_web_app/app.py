import html
import os
import json
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps
from io import StringIO
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from flask import (
    Flask,
    Response,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy.orm import joinedload
from werkzeug.security import check_password_hash, generate_password_hash

from analytics import (
    active_users_summary,
    recent_activity,
    system_counts,
    system_email_trend,
    top_spam_tokens,
    user_email_trend,
)
from chat_service import build_reply
from db_migrate import migrate_sqlite
from intel import (
    analyze_threats,
    classify_category,
    compute_risk_score,
    load_threat_db,
    risk_level,
    threat_explanation,
)
from models import EmailRecord, User, db
from retrain_service import retrain_and_save
from text_utils import PHISHING_KEYWORDS, extract_upload_text, preprocess

APP_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["SECRET_KEY"] = "spamshield-dev-key-change-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{APP_DIR / 'spam.db'}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

db.init_app(app)

_model = None
_vectorizer = None


def load_artifacts():
    global _model, _vectorizer
    if _model is None:
        _model = joblib.load(APP_DIR / "model.pkl")
    if _vectorizer is None:
        _vectorizer = joblib.load(APP_DIR / "vectorizer.pkl")
    return _model, _vectorizer


def reload_artifacts():
    global _model, _vectorizer
    _model = None
    _vectorizer = None
    return load_artifacts()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def login_required_api(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to continue.", "error")
            return redirect(url_for("login", next=request.path))
        u = g.user
        if not u or not u.is_admin:
            flash("Administrator access required.", "error")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


def admin_required_api(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        u = g.user
        if not u or not u.is_admin:
            return jsonify({"ok": False, "error": "Forbidden"}), 403
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    uid = session.get("user_id")
    user = db.session.get(User, uid) if uid else None
    return dict(current_user=user)


@app.before_request
def load_logged_in_user():
    uid = session.get("user_id")
    g.user = db.session.get(User, uid) if uid else None
    if g.user and getattr(g.user, "is_banned", False):
        ep = request.endpoint or ""
        if ep not in ("login", "signup", "verify_2fa", "static", None):
            session.clear()
            flash("Your account has been suspended.", "error")
            return redirect(url_for("login"))


def start_2fa_for_user(user: User):
    session.pop("user_id", None)
    otp = f"{secrets.randbelow(900000) + 100000:06d}"
    session["pending_2fa_user_id"] = user.id
    session["2fa_otp"] = otp
    session.permanent = True


def detect_phishing_phrases(raw_text: str):
    if not raw_text:
        return []
    lower = raw_text.lower()
    return [p for p in PHISHING_KEYWORDS if p.lower() in lower]


def suspicious_token_set(processed: str, vectorizer, model, max_tokens: int = 25):
    if not processed:
        return set()
    vocab = vectorizer.vocabulary_
    coef = np.asarray(model.coef_).ravel()
    candidates = []
    seen = set()
    for tok in processed.split():
        if tok in seen or tok not in vocab:
            continue
        seen.add(tok)
        idx = vocab[tok]
        if idx < len(coef) and coef[idx] > 0:
            candidates.append((tok, float(coef[idx])))
    candidates.sort(key=lambda x: -x[1])
    return {t for t, _ in candidates[:max_tokens]}


def top_spam_keywords(X, vectorizer, model, top_n: int = 12):
    coef = np.asarray(model.coef_).ravel()
    names = vectorizer.get_feature_names_out()
    row = X.tocsr().getrow(0)
    pairs = []
    for idx, val in zip(row.indices, row.data):
        if idx >= len(coef):
            continue
        contrib = float(val) * float(coef[idx])
        if contrib > 0:
            pairs.append((contrib, str(names[idx])))
    pairs.sort(key=lambda x: -x[0])
    return [
        {"term": term, "impact": round(score, 5)} for score, term in pairs[:top_n]
    ]


def highlight_suspicious_words(original: str, suspicious: set) -> str:
    if not original:
        return ""
    parts = re.split(r"(\b[\w']+\b)", original)
    out = []
    for part in parts:
        if not part:
            continue
        if re.fullmatch(r"[\w']+", part):
            if part.lower() in suspicious:
                out.append(
                    f'<mark class="suspicious-word">{html.escape(part)}</mark>'
                )
            else:
                out.append(html.escape(part))
        else:
            out.append(html.escape(part))
    return "".join(out)


def build_why_spam(
    is_spam: bool,
    confidence: float,
    spam_probability: float,
    top_keywords: list,
    phishing_hits: list,
    threat_lines: list,
) -> list:
    lines = []
    if is_spam:
        lines.append(
            f"The classifier labeled this message as spam with {confidence:.1f}% confidence "
            f"({spam_probability:.1f}% estimated spam probability)."
        )
        if top_keywords:
            terms = ", ".join(k["term"] for k in top_keywords[:8])
            lines.append(
                f"Terms that most strongly pushed the score toward spam include: {terms}."
            )
        if phishing_hits:
            lines.append(
                "Common phishing-style phrases were detected — verify sender and links carefully."
            )
        if not top_keywords and not phishing_hits:
            lines.append(
                "The model relied on subtle patterns across the full message rather than a few obvious keywords."
            )
    else:
        lines.append(
            f"The model considers this message likely legitimate, with {confidence:.1f}% confidence."
        )
        if top_keywords:
            lines.append(
                "Some spam-associated words appear, but overall context still leans safe."
            )
        if phishing_hits:
            lines.append(
                "Sensitive trigger phrases are present — review manually before clicking links or sharing data."
            )
    lines.extend(threat_lines)
    return lines


def predict_email(raw_text: str):
    threat_db = load_threat_db()
    model, vectorizer = load_artifacts()
    processed = preprocess(raw_text)
    if not processed:
        return None

    X = vectorizer.transform([processed])
    proba = model.predict_proba(X)[0]
    pred = int(model.predict(X)[0])
    confidence = float(max(proba)) * 100.0
    classes = list(getattr(model, "classes_", [0, 1]))
    spam_ix = classes.index(1) if 1 in classes else -1
    spam_prob = float(proba[spam_ix] if spam_ix >= 0 else proba[-1]) * 100.0

    suspicious = suspicious_token_set(processed, vectorizer, model)
    highlighted = highlight_suspicious_words(raw_text, suspicious)
    top_keywords = top_spam_keywords(X, vectorizer, model)
    phishing_hits = detect_phishing_phrases(raw_text)
    is_spam = pred == 1

    threat_type, threat_hits = analyze_threats(raw_text, threat_db)
    risk_score = compute_risk_score(spam_prob, threat_hits)
    r_level = risk_level(risk_score)
    category = classify_category(
        is_spam, raw_text, threat_type, threat_hits.get("promotion", [])
    )
    t_lines = threat_explanation(threat_type, threat_hits)

    why_spam = build_why_spam(
        is_spam,
        round(confidence, 1),
        round(spam_prob, 1),
        top_keywords,
        phishing_hits,
        t_lines,
    )

    return {
        "is_spam": is_spam,
        "prediction_label": "Spam" if is_spam else "Safe",
        "confidence": round(confidence, 1),
        "spam_probability": round(spam_prob, 1),
        "risk_score": risk_score,
        "risk_level": r_level,
        "category": category,
        "threat_type": threat_type,
        "threat_hits": {k: v for k, v in threat_hits.items() if v},
        "highlighted_html": highlighted,
        "top_keywords": top_keywords,
        "phishing_hits": phishing_hits,
        "has_phishing_keywords": len(phishing_hits) > 0,
        "why_spam": why_spam,
    }


def count_admins() -> int:
    return User.query.filter(User.role == "admin").count()


def user_dashboard_counts(user_id: int):
    q = EmailRecord.query.filter(EmailRecord.user_id == user_id)
    total = q.count()
    spam = q.filter(EmailRecord.prediction == "Spam").count()
    safe = q.filter(EmailRecord.prediction == "Safe").count()
    return total, spam, safe


def get_text_from_request():
    text = ""
    if request.is_json:
        body = request.get_json(silent=True) or {}
        text = (body.get("email_text") or "").strip()
    else:
        text = (request.form.get("email_text") or "").strip()

    upload = request.files.get("email_file")
    if upload and upload.filename:
        raw = upload.read()
        text = extract_upload_text(upload.filename, raw).strip()
    return text


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.user:
        return (
            redirect(url_for("admin_dashboard"))
            if g.user.is_admin
            else redirect(url_for("index"))
        )
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email_addr = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not username or not email_addr or not password:
            flash("All fields are required.", "error")
            return render_template("signup.html")
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("signup.html")
        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("signup.html")
        if User.query.filter_by(email=email_addr).first():
            flash("An account with this email already exists.", "error")
            return render_template("signup.html")

        first_user = User.query.count() == 0
        user = User(
            username=username,
            email=email_addr,
            password_hash=generate_password_hash(password),
            role="admin" if first_user else "user",
        )
        db.session.add(user)
        db.session.commit()
        start_2fa_for_user(user)
        flash(
            "Account created. Enter the one-time code (simulated) to finish signing in.",
            "success",
        )
        nxt = request.args.get("next")
        return redirect(url_for("verify_2fa", next=nxt) if nxt else url_for("verify_2fa"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return (
            redirect(url_for("admin_dashboard"))
            if g.user.is_admin
            else redirect(url_for("index"))
        )
    if request.method == "POST":
        email_addr = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        user = User.query.filter_by(email=email_addr).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")
        if getattr(user, "is_banned", False):
            flash("This account has been suspended.", "error")
            return render_template("login.html")
        start_2fa_for_user(user)
        flash("Enter your one-time code to complete sign-in.", "success")
        nxt = request.args.get("next")
        return redirect(url_for("verify_2fa", next=nxt) if nxt else url_for("verify_2fa"))
    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending = session.get("pending_2fa_user_id")
    if not pending:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = (request.form.get("otp") or "").strip()
        expected = session.get("2fa_otp") or ""
        if code and code == expected:
            user = db.session.get(User, pending)
            if not user or getattr(user, "is_banned", False):
                session.pop("pending_2fa_user_id", None)
                session.pop("2fa_otp", None)
                flash("This account is no longer active.", "error")
                return redirect(url_for("login"))
            session["user_id"] = pending
            session.pop("pending_2fa_user_id", None)
            session.pop("2fa_otp", None)
            flash("Signed in successfully.", "success")
            nxt = request.form.get("next") or request.args.get("next")
            if isinstance(nxt, str) and nxt.startswith("/") and not nxt.startswith("//"):
                return redirect(nxt)
            if user and user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("index"))
        flash("Invalid or expired code. Try again.", "error")

    demo_otp = session.get("2fa_otp", "")
    return render_template("verify_2fa.html", demo_otp=demo_otp)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/preview", methods=["POST"])
@login_required_api
def api_preview():
    upload = request.files.get("email_file")
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "No file uploaded"}), 400
    try:
        raw = upload.read()
        text = extract_upload_text(upload.filename, raw)
    except Exception:
        return jsonify({"ok": False, "error": "Could not read file"}), 400
    if not text.strip():
        return jsonify({"ok": False, "error": "No text extracted"}), 400
    preview = text[:8000] + ("…" if len(text) > 8000 else "")
    return jsonify(
        {
            "ok": True,
            "preview": preview,
            "length": len(text),
            "filename": upload.filename,
        }
    )


@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
@login_required_api
def api_predict():
    text = get_text_from_request()
    if not text:
        return jsonify({"ok": False, "error": "No email content to analyze"}), 400

    result = predict_email(text)
    if result is None:
        return jsonify(
            {"ok": False, "error": "After preprocessing, no text remained to analyze."}
        ), 400

    rec = EmailRecord(
        user_id=session["user_id"],
        email_text=text,
        prediction=result["prediction_label"],
        category=result["category"],
        threat_type=result["threat_type"],
        confidence=float(result["confidence"]),
        risk_score=float(result["risk_score"]),
        risk_level=result["risk_level"],
    )
    db.session.add(rec)
    db.session.commit()

    return jsonify({"ok": True, "result": result, "email_id": rec.id})


@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    total, spam, safe = user_dashboard_counts(uid)
    t_labels, t_counts = user_email_trend(uid, 14)
    return render_template(
        "dashboard.html",
        total=total,
        spam=spam,
        ham=safe,
        trend_labels=json.dumps(t_labels),
        trend_counts=json.dumps(t_counts),
    )


@app.route("/history")
@login_required
def history():
    uid = session["user_id"]
    qstr = (request.args.get("q") or "").strip()
    flt = (request.args.get("filter") or "all").lower()
    cat = (request.args.get("category") or "all").lower()
    thr = (request.args.get("threat") or "all").lower()

    query = EmailRecord.query.filter(EmailRecord.user_id == uid)
    if flt == "spam":
        query = query.filter(EmailRecord.prediction == "Spam")
    elif flt == "safe":
        query = query.filter(EmailRecord.prediction == "Safe")

    if cat != "all":
        cmap = {
            "spam": "Spam",
            "promotions": "Promotions",
            "social": "Social",
            "important": "Important",
        }
        cval = cmap.get(cat)
        if cval:
            query = query.filter(EmailRecord.category == cval)

    if thr != "all":
        tmap = {
            "phishing": "Phishing",
            "scam": "Scam",
            "promotion": "Promotion",
            "clean": "Clean",
        }
        tval = tmap.get(thr)
        if tval:
            query = query.filter(EmailRecord.threat_type == tval)

    if qstr:
        query = query.filter(EmailRecord.email_text.ilike(f"%{qstr}%"))

    rows = query.order_by(EmailRecord.created_at.desc()).limit(250).all()
    return render_template(
        "history.html",
        rows=rows,
        q=qstr,
        filter_value=flt,
        category_filter=cat,
        threat_filter=thr,
    )


def _history_rows_for_user(uid: int):
    return EmailRecord.query.filter(EmailRecord.user_id == uid).order_by(
        EmailRecord.created_at.desc()
    ).all()


@app.route("/export/history.csv")
@login_required
def export_history_csv():
    uid = session["user_id"]
    rows = _history_rows_for_user(uid)
    df = pd.DataFrame(
        [
            {
                "id": r.id,
                "preview": (r.email_text or "")[:500],
                "prediction": r.prediction,
                "category": getattr(r, "category", "") or "",
                "threat_type": getattr(r, "threat_type", "") or "",
                "confidence": r.confidence,
                "risk_score": getattr(r, "risk_score", None),
                "risk_level": getattr(r, "risk_level", "") or "",
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]
    )
    buf = StringIO()
    df.to_csv(buf, index=False)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=spamshield_history.csv"
        },
    )


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    stats = system_counts()
    t_labels, spam_c, safe_c = system_email_trend(14)
    keywords = top_spam_tokens(12)
    recent = recent_activity(8)
    active_users = active_users_summary(6)
    total_e = stats.get("emails") or 0
    spam_pct = round(100.0 * stats.get("spam", 0) / total_e, 1) if total_e else 0.0
    return render_template(
        "admin_dashboard.html",
        stats=stats,
        spam_pct=spam_pct,
        trend_labels=json.dumps(t_labels),
        trend_spam=json.dumps(spam_c),
        trend_safe=json.dumps(safe_c),
        top_keywords=keywords,
        recent_activity=recent,
        active_users=active_users,
    )


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).limit(500).all()
    return render_template("admin_users.html", users=users)


@app.route("/admin/emails")
@login_required
@admin_required
def admin_emails():
    flt = (request.args.get("filter") or "all").lower()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    q = EmailRecord.query.options(joinedload(EmailRecord.user))
    if flt == "spam":
        q = q.filter(EmailRecord.prediction == "Spam")
    elif flt == "safe":
        q = q.filter(EmailRecord.prediction == "Safe")
    if date_from:
        try:
            df = datetime.fromisoformat(date_from)
            q = q.filter(EmailRecord.created_at >= df)
        except ValueError:
            pass
    if date_to:
        try:
            end = datetime.fromisoformat(date_to) + timedelta(days=1)
            q = q.filter(EmailRecord.created_at < end)
        except ValueError:
            pass
    emails = q.order_by(EmailRecord.created_at.desc()).limit(500).all()
    return render_template(
        "admin_emails.html",
        emails=emails,
        filter_value=flt,
        date_from=date_from,
        date_to=date_to,
    )


@app.route("/admin/reports")
@login_required
@admin_required
def admin_reports():
    stats = system_counts()
    return render_template("admin_reports.html", stats=stats)


@app.route("/admin/retrain")
@app.route("/retrain")
@login_required
@admin_required
def retrain_page():
    return render_template("retrain.html")


@app.route("/api/retrain", methods=["POST"])
@login_required_api
@admin_required_api
def api_retrain():
    out = retrain_and_save(APP_DIR)
    if out.get("ok"):
        reload_artifacts()
    return jsonify({"ok": out.get("ok", False), **out})


@app.route("/api/chat", methods=["POST"])
@app.route("/chat", methods=["POST"])
@login_required_api
def api_chat():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()
    ctx = data.get("context")
    if not isinstance(ctx, dict):
        ctx = {}
    reply = build_reply(msg, ctx)
    return jsonify({"ok": True, "reply": reply})


@app.route("/assistant", methods=["POST"])
@login_required_api
def assistant():
    """
    ChatGPT-style assistant for spam/phishing guidance.

    Frontend sends JSON:
      - message: string
      - history: [{role: "user"|"assistant", content: "..."}]
    """

    system_prompt = (
        "You are an intelligent AI assistant inside a Spam Email Detection System. "
        "Help users understand spam emails, phishing risks, confidence score, risk score, "
        "and provide general helpful answers like ChatGPT."
    )

    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()
    history = data.get("history") or []

    if not msg:
        return jsonify({"ok": False, "error": "Message is required."}), 400
    if len(msg) > 2000:
        msg = msg[:2000]

    # Build OpenAI chat messages: system prompt + prior conversation.
    # Note: OpenAI accepts alternating roles; we keep what the UI sends.
    messages = [{"role": "system", "content": system_prompt}]

    if isinstance(history, list):
        for item in history[-24:]:
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            content = item.get("content")
            if role not in ("user", "assistant"):
                continue
            if content is None:
                continue
            c = str(content).strip()
            if not c:
                continue
            if len(c) > 2000:
                c = c[:2000]
            messages.append({"role": role, "content": c})

    # Ensure the latest user message is present at the end.
    if not messages or messages[-1].get("role") != "user" or messages[-1].get(
        "content"
    ) != msg:
        messages.append({"role": "user", "content": msg})

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return jsonify({"ok": False, "error": "OPENAI_API_KEY is not set on the server."}), 500

    try:
        try:
            from openai import OpenAI  # type: ignore
        except ImportError:
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "openai package not installed. Run: pip install openai",
                    }
                ),
                500,
            )

        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=messages,
            temperature=0.4,
        )
        reply = (
            (resp.choices[0].message.content if resp.choices else "") or ""
        ).strip()
        if not reply:
            reply = "I couldn’t generate a response. Please try again."
        return jsonify({"ok": True, "reply": reply})
    except Exception as e:
        # Avoid leaking sensitive details; still provide a useful summary.
        err = str(e)[:300] if e else "Unknown AI error"
        return jsonify({"ok": False, "error": f"AI request failed: {err}"}), 500


@app.route("/api/admin/users/<int:user_id>/ban", methods=["POST"])
@login_required_api
@admin_required_api
def api_admin_user_ban(user_id: int):
    actor = session["user_id"]
    if user_id == actor:
        return jsonify({"ok": False, "error": "You cannot ban your own account."}), 400
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"ok": False, "error": "User not found."}), 404
    u.is_banned = True
    db.session.commit()
    return jsonify({"ok": True, "message": "User banned."})


@app.route("/api/admin/users/<int:user_id>/unban", methods=["POST"])
@login_required_api
@admin_required_api
def api_admin_user_unban(user_id: int):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"ok": False, "error": "User not found."}), 404
    u.is_banned = False
    db.session.commit()
    return jsonify({"ok": True, "message": "User unbanned."})


@app.route("/api/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required_api
@admin_required_api
def api_admin_user_delete(user_id: int):
    actor = session["user_id"]
    if user_id == actor:
        return jsonify({"ok": False, "error": "You cannot delete your own account."}), 400
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"ok": False, "error": "User not found."}), 404
    if u.is_admin and count_admins() <= 1:
        return jsonify({"ok": False, "error": "Cannot delete the last administrator."}), 400
    db.session.delete(u)
    db.session.commit()
    return jsonify({"ok": True, "message": "User deleted."})


@app.route("/api/admin/users/<int:user_id>/reset-password", methods=["POST"])
@login_required_api
@admin_required_api
def api_admin_user_reset_password(user_id: int):
    u = db.session.get(User, user_id)
    if not u:
        return jsonify({"ok": False, "error": "User not found."}), 404
    data = request.get_json(silent=True) or {}
    pw = (data.get("password") or "").strip()
    if len(pw) < 8:
        return jsonify({"ok": False, "error": "Password must be at least 8 characters."}), 400
    u.password_hash = generate_password_hash(pw)
    db.session.commit()
    return jsonify({"ok": True, "message": "Password updated."})


@app.route("/api/admin/emails/<int:email_id>/delete", methods=["POST"])
@login_required_api
@admin_required_api
def api_admin_email_delete(email_id: int):
    rec = db.session.get(EmailRecord, email_id)
    if not rec:
        return jsonify({"ok": False, "error": "Record not found."}), 404
    db.session.delete(rec)
    db.session.commit()
    return jsonify({"ok": True, "message": "Email record deleted."})


@app.route("/export/admin/emails.csv")
@login_required
@admin_required
def export_admin_emails():
    rows = EmailRecord.query.order_by(EmailRecord.created_at.desc()).limit(5000).all()
    df = pd.DataFrame(
        [
            {
                "id": r.id,
                "user_id": r.user_id,
                "preview": (r.email_text or "")[:800],
                "prediction": r.prediction,
                "category": getattr(r, "category", ""),
                "threat_type": getattr(r, "threat_type", ""),
                "confidence": r.confidence,
                "risk_score": getattr(r, "risk_score", None),
                "created_at": r.created_at.isoformat() if r.created_at else "",
            }
            for r in rows
        ]
    )
    buf = StringIO()
    df.to_csv(buf, index=False)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=system_emails.csv"},
    )


@app.route("/export/admin/users.csv")
@login_required
@admin_required
def export_admin_users():
    rows = User.query.order_by(User.created_at.desc()).all()
    df = pd.DataFrame(
        [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_banned": getattr(u, "is_banned", False),
                "created_at": u.created_at.isoformat() if u.created_at else "",
            }
            for u in rows
        ]
    )
    buf = StringIO()
    df.to_csv(buf, index=False)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"},
    )


@app.route("/api/dashboard-stats")
@login_required_api
def api_dashboard_stats():
    uid = session["user_id"]
    total, spam, safe = user_dashboard_counts(uid)
    return jsonify({"ok": True, "total": total, "spam": spam, "ham": safe})


with app.app_context():
    db.create_all()
    migrate_sqlite()
    load_artifacts()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
