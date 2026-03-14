import os
from typing import List, Optional

try:
    from pydantic_settings import BaseSettings
    from pydantic import ConfigDict
except Exception:
    try:
        from pydantic import BaseSettings, ConfigDict
    except Exception:
        from pydantic import BaseModel
        BaseSettings = BaseModel
        ConfigDict = lambda **kwargs: {"env_file": ".env", "extra": "ignore"}
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    model_config = ConfigDict(env_file=".env", extra="ignore")
    # Project metadata
    PROJECT_NAME: str = "SENTINEL-AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    HYBRIDANALYSIS_API_KEY: str = os.getenv("HYBRIDANALYSIS_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./test.db")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # Security
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "your-secret-key-here-change-in-production"
    )
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )

    # Application
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    # Pydantic will attempt to `json.loads` values for non-str annotation types
    # when loading from the environment (including .env file).  That behaviour
    # is convenient when you store JSON in your environment, but most of our
    # settings are provided as simple comma-separated strings.  If the
    # variable isn't valid JSON the loader raises a `JSONDecodeError` during
    # model construction *before* any validators are executed (see test
    # failures above).  To avoid the problem we keep the raw field a `str`
    # and expose a helper property that returns the cleaned list.

    # fields stored as simple strings so pydantic won't try to JSON-decode them.
    # the public accessor methods below convert to lists lazily.  This keeps
    # compatibility with the rest of the codebase which expects lists.
    ALLOWED_HOSTS: str = os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1")
    CORS_ORIGINS: str = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:8080"
    )
    BACKEND_CORS_ORIGINS: str = os.getenv(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:8080"
    )

    @property
    def allowed_hosts_list(self) -> List[str]:
        # keep old-capitalization names for code that previously referenced
        # ``settings.ALLOWED_HOSTS``; they will now call this property instead
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",") if h.strip()]

    @property
    def cors_origins_list(self) -> List[str]:
        return [h.strip() for h in self.CORS_ORIGINS.split(",") if h.strip()]

    @property
    def backend_cors_origins_list(self) -> List[str]:
        return [h.strip() for h in self.BACKEND_CORS_ORIGINS.split(",") if h.strip()]
    SMTP_USERNAME: Optional[str] = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", "alerts@sentinel-ai.com")

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    API_CACHE_TTL: int = int(os.getenv("API_CACHE_TTL", "300"))

    # External intelligence API policy
    # Default local-only analysis to protect third-party API quotas.
    EXTERNAL_APIS_ENABLED: bool = os.getenv("EXTERNAL_APIS_ENABLED", "False").lower() == "true"

    # File upload
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES: List[str] = [
        ".exe",
        ".dll",
        ".py",
        ".js",
        ".php",
        ".jar",
        ".apk",
        ".pdf",
        ".doc",
        ".docx",
    ]

    # AI / Gemini
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")


settings = Settings()
