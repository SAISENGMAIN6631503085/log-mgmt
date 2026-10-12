from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All config comes from env vars (see .env.example); no config files to keep in sync."""

    postgres_user: str = "logmgmt"
    postgres_password: str = ""
    postgres_db: str = "logmgmt"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    jwt_secret: str = ""
    default_tenant: str = "demoA"
    retention_days: int = 7
    alert_webhook_url: str = ""

    @property
    def database_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
