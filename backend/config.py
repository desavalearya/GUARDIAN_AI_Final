from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Guardian AI"
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
    hmac_secret: str = ""
    vault_secret: str = ""


settings = Settings()
