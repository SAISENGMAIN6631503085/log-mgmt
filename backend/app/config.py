from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All config comes from env vars (see .env.example); no config files to keep in sync."""

    postgres_user: str = "logmgmt"
    postgres_password: str = ""
    postgres_db: str = "logmgmt"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    jwt_secret: str = ""
    jwt_expire_minutes: int = 480  # one working day; there are no refresh tokens in this demo
    default_tenant: str = "demoA"
    syslog_tenant_map: str = ""  # parsed by normalizers.syslog.parse_tenant_map
    # Shared secret Vector sends to /api/ingest/syslog (that endpoint has no per-tenant API key)
    syslog_ingest_token: str = ""
    # Demo ingest keys created by `make seed`: "tenant=key,tenant=key"
    seed_api_keys: str = ""
    # Passwords for the demo users created by `make seed` (admin, viewerA, viewerB)
    seed_admin_password: str = ""
    seed_viewer_password: str = ""
    retention_days: int = 7
    alert_webhook_url: str = ""
    alert_interval_seconds: int = 60
    # IP -> country database, downloaded at image build time (see fetch_geoip.py)
    geoip_db: str = "/app/geoip/dbip-country-lite.mmdb"
    # "demo" means the simulator service runs, so the website labels the data as generated
    compose_profiles: str = ""

    @property
    def demo_data(self) -> bool:
        return "demo" in self.compose_profiles.split(",")

    @property
    def database_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
