from fastapi import APIRouter, Depends, HTTPException, status
from urllib.parse import urlencode
from sqlalchemy.orm import Session

from backend.api.deps import get_current_user
from backend.auth.security import create_access_token, hash_password, verify_password
from backend.database import get_db
from backend.config import settings
from backend.models import Organization, User
from backend.schemas import LoginRequest, RegisterRequest, TokenResponse, UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter(User.email == body.email.lower()).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    organization = db.query(Organization).filter(
        Organization.slug == settings.default_org_slug
    ).one_or_none()
    user = User(
        email=body.email.lower(),
        hashed_password=hash_password(body.password),
        role=body.role,
        organization_id=organization.id if organization else None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if user is None or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(subject=str(user.id), role=user.role)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.get("/oidc/config")
def oidc_config() -> dict:
    enabled = bool(settings.oidc_issuer and settings.oidc_client_id)
    authorize_url = None
    if enabled:
        authorize_url = settings.oidc_issuer.rstrip("/") + "/authorize?" + urlencode(
            {
                "client_id": settings.oidc_client_id,
                "redirect_uri": settings.oidc_redirect_uri,
                "response_type": "code",
                "scope": "openid email profile",
            }
        )
    return {
        "enabled": enabled,
        "issuer": settings.oidc_issuer if enabled else None,
        "authorize_url": authorize_url,
        "note": "Configure the issuer/client and secret before enabling SSO. Local JWT login remains available.",
    }
