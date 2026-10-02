from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse

from backend.detection.url_heuristics import score_one_url
from backend.email.link_rewrite import url_from_token
from backend.email.parser import _domain

router = APIRouter(tags=["click-time-protection"])


@router.get("/r/{token}")
def check_and_redirect(token: str):
    try:
        url = url_from_token(token)
    except ValueError as exc:
        raise HTTPException(status_code=410, detail=str(exc)) from exc

    heuristic_score, reasons = score_one_url(url, _domain(url))
    score = heuristic_score
    backend = "heuristics"
    try:
        from backend.detection import url_ml

        if url_ml.available():
            score = max(score, url_ml.score_url(url))
            backend = "url-xgb-v1+heuristics"
    except Exception:
        pass
    if score >= 0.7:
        raise HTTPException(
            status_code=451,
            detail={
                "message": "PhishProof blocked this destination at click time.",
                "risk_score": round(score, 3),
                "backend": backend,
                "reasons": reasons,
            },
        )
    return RedirectResponse(url=url, status_code=307)
