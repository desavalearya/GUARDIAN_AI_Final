from backend.auth.security import hash_password
from backend.database import SessionLocal
from backend.email.parser import build_rfc822
from backend.email.pipeline import ingest_and_analyze
from backend.models import Email, User

DEMO_USERS = (
    ("analyst@example.com", "changeme1", "analyst"),
    ("user@example.com", "changeme1", "user"),
)

SAMPLES = (
    (
        "alice@company.com",
        "user@example.com",
        "Weekly status",
        "Hi team, the weekly notes are in the shared drive. See you Monday.",
        "inbound",
    ),
    (
        "PayPal Security <help@secure-paypal.xyz>",
        "user@example.com",
        "Urgent: verify your account",
        "Your account will be closed. Click here to confirm your password: http://secure-paypal.xyz/login/verify",
        "inbound",
    ),
    (
        "it-admin@company.com",
        "user@example.com",
        "VPN token",
        "Please use this one-time password 482193 if you requested it. Otherwise ignore.",
        "inbound",
    ),
)


def seed_demo_users() -> None:
    db = SessionLocal()
    try:
        for email, password, role in DEMO_USERS:
            existing = db.query(User).filter(User.email == email).first()
            if existing is None:
                db.add(User(email=email, hashed_password=hash_password(password), role=role))
        db.commit()
        if db.query(Email).count() == 0:
            for sender, recipient, subject, body, direction in SAMPLES:
                raw = build_rfc822(sender, recipient, subject, body)
                ingest_and_analyze(db, raw, direction=direction, ingestion_path="seed")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
