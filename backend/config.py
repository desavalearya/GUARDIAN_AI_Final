from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "PhishProof"
    database_url: str = "postgresql+psycopg://guardian:guardian@postgres:5432/guardian"
    redis_url: str = "redis://redis:6379/0"
    celery_broker_url: str = "redis://redis:6379/0"
    celery_result_backend: str = "redis://redis:6379/1"
    jwt_secret: str = "change-me-to-a-long-random-string"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    model_dir: str = "/app/models"
    data_dir: str = "/app/data"
    ingest_api_key: str = "dev-ingest-key"
    postfix_host: str = "postfix"
    postfix_submission_port: int = 587
    mail_domain: str = "guardian.local"
    mailpit_url: str = "http://receiver:8025"
    demo_receiver_address: str = "receiver@company-b.test"
    demo_receiver_domain: str = "company-b.test"
    # Dedicated secrets — do not reuse jwt_secret (vault/HMAC rotation must be independent).
    hmac_secret: str = "change-me-hmac-secret-not-jwt"
    vault_secret: str = "change-me-vault-secret-not-jwt"
    cors_origins: str = (
        "http://localhost:5173,http://localhost:5174,"
        "http://127.0.0.1:5173,http://127.0.0.1:5174"
    )
    max_attachment_bytes: int = 25_000_000
    max_zip_member_bytes: int = 50_000_000
    # Inference modes: adaptive (recommended), full (all models inline), fast (no heavy models).
    analysis_mode: str = "adaptive"
    deep_sync_min_risk: float = 15.0
    deep_sync_max_risk: float = 90.0
    async_deep_enabled: bool = True
    url_cache_ttl_seconds: int = 86_400
    smtp_scan_timeout_seconds: int = 20
    siem_webhook_url: str = ""
    siem_hmac_secret: str = "change-me-siem-secret"
    siem_timeout_seconds: int = 5
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60
    clamav_enabled: bool = True
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_timeout_seconds: int = 5
    yara_rules_path: str = "/app/data/yara"
    url_rewrite_enabled: bool = True
    url_rewrite_secret: str = "change-me-url-rewrite-secret"
    public_api_url: str = "http://localhost:8000"
    url_rewrite_ttl_seconds: int = 604_800
    default_org_slug: str = "default"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    connector_webhook_secret: str = "change-me-connector-secret"
    m365_tenant_id: str = ""
    m365_client_id: str = ""
    google_service_account_file: str = ""
    oidc_redirect_uri: str = "http://localhost:8000/api/v1/auth/oidc/callback"


settings = Settings()
