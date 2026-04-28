from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(16), nullable=False, default="user", index=True)
    is_banned = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    emails = db.relationship(
        "EmailRecord",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @property
    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"


class EmailRecord(db.Model):
    __tablename__ = "emails"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    email_text = db.Column(db.Text, nullable=False)
    prediction = db.Column(db.String(16), nullable=False)
    category = db.Column(db.String(32), nullable=False, default="Important")
    threat_type = db.Column(db.String(32), nullable=False, default="Clean")
    confidence = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    risk_level = db.Column(db.String(16), nullable=False, default="Medium")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
