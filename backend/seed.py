from backend.auth.security import hash_password
from backend.database import SessionLocal
from backend.email.parser import build_rfc822
from backend.email.pipeline import ingest_and_analyze
from backend.models import Email, Organization, User

DEMO_USERS = (
    ("analyst@example.com", "changeme1", "analyst"),
    ("approver@example.com", "changeme1", "admin"),
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
        org = db.query(Organization).filter(Organization.slug == "default").one_or_none()
        if org is None:
            org = Organization(
                slug="default",
                name="PhishProof Demo Organisation",
                domains=["example.com", "company-b.test"],
            )
            db.add(org)
            db.flush()
        for email, password, role in DEMO_USERS:
            existing = db.query(User).filter(User.email == email).first()
            if existing is None:
                db.add(
                    User(
                        email=email,
                        hashed_password=hash_password(password),
                        role=role,
                        organization_id=org.id,
                    )
                )
            elif existing.organization_id is None:
                existing.organization_id = org.id
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
