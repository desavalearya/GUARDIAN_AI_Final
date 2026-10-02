"""Privacy-safe Fraud DNA generation and post-decision campaign clustering."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.cases.service import campaign_keys
from backend.models import Campaign, Email, FraudFingerprint

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}", re.I)


def _simhash(text: str) -> str:
    tokens = TOKEN_RE.findall(text.lower())
    vector = [0] * 64
    for token, count in Counter(tokens).items():
        digest = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            vector[bit] += count if digest & (1 << bit) else -count
    value = sum(1 << bit for bit, weight in enumerate(vector) if weight >= 0)
    return f"{value:016x}"


def _hamming_similarity(left: str, right: str) -> float:
    return 1.0 - ((int(left, 16) ^ int(right, 16)).bit_count() / 64.0)


def _hashing_embedding(text: str) -> tuple[list[float], str]:
    from sklearn.feature_extraction.text import HashingVectorizer

    vectorizer = HashingVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        n_features=128,
        alternate_sign=False,
        norm="l2",
    )
    values = vectorizer.transform([text]).toarray()[0]
    return [round(float(value), 6) for value in values], "hashing-char-v1"


def _cosine(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    ln = math.sqrt(sum(a * a for a in left))
    rn = math.sqrt(sum(b * b for b in right))
    return dot / (ln * rn) if ln and rn else 0.0


def _techniques(email: Email) -> list[str]:
    tags: set[str] = set()
    for detector in email.detector_results:
        if detector.raw_score < 0.4:
            continue
        if detector.detector_name == "lure_heuristics":
            tags.update((detector.evidence or {}).get("reasons") or [])
        else:
            tags.add(detector.detector_name)
    return sorted(tags)


def _jaccard(left: list[str], right: list[str]) -> float:
    a, b = set(left), set(right)
    return len(a & b) / len(a | b) if a or b else 0.0


def _similarity(
    fuzzy_hash: str,
    embedding: list[float],
    keys: list[str],
    other: FraudFingerprint,
) -> float:
    fuzzy = _hamming_similarity(fuzzy_hash, other.fuzzy_hash)
    semantic = _cosine(embedding, [float(item) for item in other.embedding])
    infra = _jaccard(keys, list(other.infrastructure_keys or []))
    return round((0.35 * fuzzy) + (0.45 * semantic) + (0.20 * infra), 4)


def build_and_cluster(db: Session, email: Email) -> FraudFingerprint:
    """Create Fraud DNA and attach the email to the nearest credible campaign."""
    text = f"{email.subject}\n{email.body_plain}".strip().lower()
    fuzzy_hash = _simhash(text)
    embedding, embedding_version = _hashing_embedding(text)
    keys = campaign_keys(email)
    techniques = _techniques(email)

    best: FraudFingerprint | None = None
    best_score = 0.0
    candidates = (
        db.query(FraudFingerprint)
        .join(Email, Email.id == FraudFingerprint.email_id)
        .filter(FraudFingerprint.email_id != email.id)
        .filter(Email.organization_id == email.organization_id)
        .order_by(FraudFingerprint.created_at.desc())
        .limit(500)
        .all()
    )
    for candidate in candidates:
        if candidate.embedding_version != embedding_version:
            continue
        score = _similarity(fuzzy_hash, embedding, keys, candidate)
        if score > best_score:
            best, best_score = candidate, score

    fingerprint = email.fraud_dna or FraudFingerprint(email_id=email.id)
    fingerprint.fuzzy_hash = fuzzy_hash
    fingerprint.embedding = embedding
    fingerprint.embedding_version = embedding_version
    fingerprint.technique_tags = techniques
    fingerprint.infrastructure_keys = keys
    fingerprint.nearest_email_id = best.email_id if best else None
    fingerprint.similarity = best_score
    if email.fraud_dna is None:
        db.add(fingerprint)
        email.fraud_dna = fingerprint

    if best is not None and best_score >= 0.72:
        peer = db.query(Email).filter(Email.id == best.email_id).one_or_none()
        if peer and peer.campaign_id:
            email.campaign_id = peer.campaign_id
    db.flush()

    if email.campaign:
        campaign = email.campaign
        member_ids = [member.id for member in campaign.emails]
        member_fps = (
            db.query(FraudFingerprint)
            .filter(FraudFingerprint.email_id.in_(member_ids))
            .all()
            if member_ids
            else []
        )
        all_tags = Counter(
            tag for fp in member_fps for tag in (fp.technique_tags or [])
        )
        recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        recent = sum(
            1
            for member in campaign.emails
            if member.received_at and member.received_at >= recent_cutoff
        )
        campaign.growth_rate_flag = recent >= 3
        campaign.dna_summary = {
            "top_techniques": [name for name, _ in all_tags.most_common(6)],
            "latest_similarity": best_score,
            "fingerprint_count": len(member_fps),
            "recent_24h": recent,
        }
    return fingerprint
