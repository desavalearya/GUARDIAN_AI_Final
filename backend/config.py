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
    # Dedicated secrets — do not reuse jwt_secret (vault/HMAC rotation must be independent).
    hmac_secret: str = "change-me-hmac-secret-not-jwt"
    vault_secret: str = "change-me-vault-secret-not-jwt"
    cors_origins: str = (
        "http://localhost:5173,http://localhost:5174,"
        "http://127.0.0.1:5173,http://127.0.0.1:5174"
    )
    max_attachment_bytes: int = 25_000_000
    max_zip_member_bytes: int = 50_000_000


settings = Settings()
