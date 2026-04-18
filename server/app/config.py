import os
import socket
from typing import List, Optional
from pathlib import Path

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

# Always load .env from project root (not .env.example)
from dotenv import load_dotenv, find_dotenv

# Calculate absolute path to project root (parent of parent of this file's parent)
# This file is at: /path/to/SENTINELAI-main/server/app/config.py
# Project root is: /path/to/SENTINELAI-main
PROJECT_ROOT = Path(__file__).parent.parent.parent  # Go up 3 levels from config.py
ENV_FILE = PROJECT_ROOT / ".env"

# Load .env with absolute path (works regardless of working directory)
if ENV_FILE.exists():
    load_dotenv(str(ENV_FILE))
else:
    # Fallback: try to find .env using find_dotenv
    env_path = find_dotenv('.env', raise_error_if_not_found=False)
    if env_path:
        load_dotenv(env_path)


def _primary_local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        sock.close()
        return str(ip_address).strip()
    except Exception:
        return "127.0.0.1"


def _primary_local_hostname() -> str:
    try:
        return socket.getfqdn() or socket.gethostname() or "localhost"
    except Exception:
        return "localhost"


class Settings(BaseSettings):
    # SentinelAI Client Master Password and Admin Email
    MASTER_CLIENT_PASSWORD: str = os.getenv("MASTER_CLIENT_PASSWORD", "changeme-please")
    ADMIN_EMAIL: str = os.getenv("ADMIN_EMAIL", "raviranbir007@gmail.com")
    model_config = ConfigDict(env_file=str(ENV_FILE), extra="ignore")
    # Project metadata
    PROJECT_NAME: str = "SENTINEL-AI"
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    HYBRIDANALYSIS_API_KEY: str = os.getenv("HYBRIDANALYSIS_API_KEY", "") or os.getenv("HYBRID_ANALYSIS_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "") or os.getenv("URLSCANIO_API_KEY", "")

    # Database
    DATABASE_URL: str = "sqlite:///./server/test.db"
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

    @property
    def gemini_api_keys_list(self) -> List[str]:
        """Get all Gemini API keys from various sources as a single list"""
        keys = []
        seen = set()
        
        # Add primary key if set
        if self.GEMINI_API_KEY and self.GEMINI_API_KEY not in seen:
            keys.append(self.GEMINI_API_KEY)
            seen.add(self.GEMINI_API_KEY)
        
        # Add CSV keys from GEMINI_API_KEYS
        for key in self.GEMINI_API_KEYS.split(","):
            key = key.strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        # Add numbered keys GEMINI_API_KEY_1 through GEMINI_API_KEY_20
        for i in range(1, 21):
            key = getattr(self, f"GEMINI_API_KEY_{i}", "").strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        # Add CSV keys from GOOGLE_API_KEYS (alternative naming)
        for key in self.GOOGLE_API_KEYS.split(","):
            key = key.strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        # Add numbered GOOGLE keys
        for i in range(1, 6):
            key = getattr(self, f"GOOGLE_API_KEY_{i}", "").strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        return keys

    @property
    def openai_api_keys_list(self) -> List[str]:
        """Get all OpenAI API keys from various sources as a single list"""
        keys = []
        seen = set()
        
        # Add primary key if set
        if self.OPENAI_API_KEY and self.OPENAI_API_KEY not in seen:
            keys.append(self.OPENAI_API_KEY)
            seen.add(self.OPENAI_API_KEY)
        
        # Add CSV keys from OPENAI_API_KEYS
        for key in self.OPENAI_API_KEYS.split(","):
            key = key.strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        # Add numbered keys OPENAI_API_KEY_1 through OPENAI_API_KEY_5
        for i in range(1, 6):
            key = getattr(self, f"OPENAI_API_KEY_{i}", "").strip()
            if key and key not in seen:
                keys.append(key)
                seen.add(key)
        
        return keys

    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME: Optional[str] = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = os.getenv("SMTP_PASSWORD")
    FROM_EMAIL: str = os.getenv("FROM_EMAIL", "alerts@sentinel-ai.com")
    ALERT_EMAIL: Optional[str] = os.getenv("ALERT_EMAIL", os.getenv("SMTP_USERNAME") or "raviranbir007@gmail.com")
    CLIENT_REGISTRATION_ALERT_EMAILS: str = os.getenv("CLIENT_REGISTRATION_ALERT_EMAILS", "raviranbir007@gmail.com")
    ADMIN_INFRA_HOSTNAMES: str = os.getenv("ADMIN_INFRA_HOSTNAMES", _primary_local_hostname())
    ADMIN_INFRA_IPS: str = os.getenv("ADMIN_INFRA_IPS", _primary_local_ip())

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    API_CACHE_TTL: int = int(os.getenv("API_CACHE_TTL", "300"))

    # External intelligence API policy
    # Default to enabled so configured API keys are actually exercised.
    # Set EXTERNAL_APIS_ENABLED=false explicitly to force local-only analysis.
    EXTERNAL_APIS_ENABLED: bool = os.getenv("EXTERNAL_APIS_ENABLED", "True").lower() == "true"

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
    GEMINI_API_KEYS: str = os.getenv("GEMINI_API_KEYS", "")
    GOOGLE_API_KEYS: str = os.getenv("GOOGLE_API_KEYS", "")
    
    # Gemini numbered API keys (supports up to 20 keys)
    GEMINI_API_KEY_1: str = os.getenv("GEMINI_API_KEY_1", "")
    GEMINI_API_KEY_2: str = os.getenv("GEMINI_API_KEY_2", "")
    GEMINI_API_KEY_3: str = os.getenv("GEMINI_API_KEY_3", "")
    GEMINI_API_KEY_4: str = os.getenv("GEMINI_API_KEY_4", "")
    GEMINI_API_KEY_5: str = os.getenv("GEMINI_API_KEY_5", "")
    GEMINI_API_KEY_6: str = os.getenv("GEMINI_API_KEY_6", "")
    GEMINI_API_KEY_7: str = os.getenv("GEMINI_API_KEY_7", "")
    GEMINI_API_KEY_8: str = os.getenv("GEMINI_API_KEY_8", "")
    GEMINI_API_KEY_9: str = os.getenv("GEMINI_API_KEY_9", "")
    GEMINI_API_KEY_10: str = os.getenv("GEMINI_API_KEY_10", "")
    GEMINI_API_KEY_11: str = os.getenv("GEMINI_API_KEY_11", "")
    GEMINI_API_KEY_12: str = os.getenv("GEMINI_API_KEY_12", "")
    GEMINI_API_KEY_13: str = os.getenv("GEMINI_API_KEY_13", "")
    GEMINI_API_KEY_14: str = os.getenv("GEMINI_API_KEY_14", "")
    GEMINI_API_KEY_15: str = os.getenv("GEMINI_API_KEY_15", "")
    GEMINI_API_KEY_16: str = os.getenv("GEMINI_API_KEY_16", "")
    GEMINI_API_KEY_17: str = os.getenv("GEMINI_API_KEY_17", "")
    GEMINI_API_KEY_18: str = os.getenv("GEMINI_API_KEY_18", "")
    GEMINI_API_KEY_19: str = os.getenv("GEMINI_API_KEY_19", "")
    GEMINI_API_KEY_20: str = os.getenv("GEMINI_API_KEY_20", "")
    
    # Google numbered API keys (alternative naming)
    GOOGLE_API_KEY_1: str = os.getenv("GOOGLE_API_KEY_1", "")
    GOOGLE_API_KEY_2: str = os.getenv("GOOGLE_API_KEY_2", "")
    GOOGLE_API_KEY_3: str = os.getenv("GOOGLE_API_KEY_3", "")
    GOOGLE_API_KEY_4: str = os.getenv("GOOGLE_API_KEY_4", "")
    GOOGLE_API_KEY_5: str = os.getenv("GOOGLE_API_KEY_5", "")
    
    # Gemini Model and Report Generation Configuration
    GEMINI_MODEL_CANDIDATES: str = os.getenv("GEMINI_MODEL_CANDIDATES", "gemini-1.5-flash,gemini-2.5-flash,gemini-1.5-pro")
    GEMINI_DAILY_REPORT_LIMIT: int = int(os.getenv("GEMINI_DAILY_REPORT_LIMIT", "80"))
    GEMINI_HOURLY_REPORT_LIMIT: int = int(os.getenv("GEMINI_HOURLY_REPORT_LIMIT", "20"))
    GEMINI_EXECUTIVE_ONLY: bool = os.getenv("GEMINI_EXECUTIVE_ONLY", "false").lower() in {"1", "true", "yes", "on"}
    GEMINI_QUOTA_COOLDOWN_SECONDS: int = int(os.getenv("GEMINI_QUOTA_COOLDOWN_SECONDS", "900"))
    GEMINI_ANALYSIS_CACHE_TTL_SECONDS: int = int(os.getenv("GEMINI_ANALYSIS_CACHE_TTL_SECONDS", "1800"))
    GEMINI_ANALYSIS_CACHE_SIZE: int = int(os.getenv("GEMINI_ANALYSIS_CACHE_SIZE", "64"))
    GEMINI_MIN_REQUEST_INTERVAL: float = float(os.getenv("GEMINI_MIN_REQUEST_INTERVAL", "2.0"))
    GEMINI_MAX_ATTEMPTS: int = int(os.getenv("GEMINI_MAX_ATTEMPTS", "3"))
    GEMINI_CIRCUIT_THRESHOLD: int = int(os.getenv("GEMINI_CIRCUIT_THRESHOLD", "5"))
    GEMINI_CIRCUIT_OPEN_SECONDS: int = int(os.getenv("GEMINI_CIRCUIT_OPEN_SECONDS", "60"))
    GEMINI_REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("GEMINI_REQUEST_TIMEOUT_SECONDS", "45"))
    
    # OpenAI API Keys (for future AI integration)
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_API_KEY_1: str = os.getenv("OPENAI_API_KEY_1", "")
    OPENAI_API_KEY_2: str = os.getenv("OPENAI_API_KEY_2", "")
    OPENAI_API_KEY_3: str = os.getenv("OPENAI_API_KEY_3", "")
    OPENAI_API_KEY_4: str = os.getenv("OPENAI_API_KEY_4", "")
    OPENAI_API_KEY_5: str = os.getenv("OPENAI_API_KEY_5", "")
    OPENAI_API_KEYS: str = os.getenv("OPENAI_API_KEYS", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4-turbo")
    OPENAI_ORG_ID: str = os.getenv("OPENAI_ORG_ID", "")

    # Defense decisioning controls (network-defense)
    SENTINEL_AUTO_BLOCK_MIN_SEVERITY: str = os.getenv("SENTINEL_AUTO_BLOCK_MIN_SEVERITY", "high")
    SENTINEL_ENABLE_MANUAL_APPROVAL: bool = os.getenv("SENTINEL_ENABLE_MANUAL_APPROVAL", "True").lower() == "true"
    SENTINEL_MANUAL_REVIEW_MIN_CONFIDENCE: float = float(os.getenv("SENTINEL_MANUAL_REVIEW_MIN_CONFIDENCE", "0.65"))
    
    # Sentinel API Governance & Performance Configuration
    SENTINEL_API_MAX_CONCURRENT_CALLS: int = int(os.getenv("SENTINEL_API_MAX_CONCURRENT_CALLS", "12"))
    SENTINEL_API_QUEUE_WAIT_TIMEOUT: float = float(os.getenv("SENTINEL_API_QUEUE_WAIT_TIMEOUT", "2.0"))
    SENTINEL_API_FAILURE_THRESHOLD: int = int(os.getenv("SENTINEL_API_FAILURE_THRESHOLD", "4"))
    SENTINEL_API_CIRCUIT_COOLDOWN_SECONDS: float = float(os.getenv("SENTINEL_API_CIRCUIT_COOLDOWN_SECONDS", "90"))
    SENTINEL_API_BUDGET_DAILY: int = int(os.getenv("SENTINEL_API_BUDGET_DAILY", "5000"))
    
    # Sentinel Adaptive Hardening & Monitoring
    SENTINEL_ENABLE_STARTUP_MONITORS: bool = os.getenv("SENTINEL_ENABLE_STARTUP_MONITORS", "true").lower() in {"1", "true", "yes", "on"}
    SENTINEL_ESCALATE_EXTERNAL_API_ON_THREAT: bool = os.getenv("SENTINEL_ESCALATE_EXTERNAL_API_ON_THREAT", "true").lower() in {"1", "true", "yes", "on"}
    SENTINEL_ENABLE_NETWORK_MONITORING: bool = os.getenv("SENTINEL_ENABLE_NETWORK_MONITORING", "true").lower() in {"1", "true", "yes", "on"}
    SENTINEL_MONITOR_STATUS_INTERVAL: int = int(os.getenv("SENTINEL_MONITOR_STATUS_INTERVAL", "3600"))
    SENTINEL_NETWORK_SCAN_COOLDOWN: int = int(os.getenv("SENTINEL_NETWORK_SCAN_COOLDOWN", "600"))
    SENTINEL_NETWORK_POLL_INTERVAL: int = int(os.getenv("SENTINEL_NETWORK_POLL_INTERVAL", "15"))
    SENTINEL_SCAN_LOCAL_TARGETS: bool = os.getenv("SENTINEL_SCAN_LOCAL_TARGETS", "false").lower() in {"1", "true", "yes", "on"}
    SENTINEL_PROMPT_COOLDOWN: int = int(os.getenv("SENTINEL_PROMPT_COOLDOWN", "900"))
    SENTINEL_URL_REVISIT_COOLDOWN: int = int(os.getenv("SENTINEL_URL_REVISIT_COOLDOWN", "60"))
    SENTINEL_BROWSER_HISTORY_BATCH: int = int(os.getenv("SENTINEL_BROWSER_HISTORY_BATCH", "1000"))
    SENTINEL_DOWNLOAD_POLL_INTERVAL: int = int(os.getenv("SENTINEL_DOWNLOAD_POLL_INTERVAL", "15"))
    SENTINEL_DOWNLOAD_SETTLE_SECONDS: int = int(os.getenv("SENTINEL_DOWNLOAD_SETTLE_SECONDS", "20"))
    SENTINEL_DOWNLOAD_MAX_FILE_SIZE: int = int(os.getenv("SENTINEL_DOWNLOAD_MAX_FILE_SIZE", str(150 * 1024 * 1024)))
    SENTINEL_PROMPT_DUPLICATE_SUPPRESS_SECONDS: int = int(os.getenv("SENTINEL_PROMPT_DUPLICATE_SUPPRESS_SECONDS", "5"))
    SENTINEL_BROWSER_HISTORY_PATHS: str = os.getenv("SENTINEL_BROWSER_HISTORY_PATHS", "")
    SENTINEL_DETECTOR_THRESHOLD_PROFILES_JSON: str = os.getenv("SENTINEL_DETECTOR_THRESHOLD_PROFILES_JSON", "")
    SENTINEL_DETECTOR_CALIBRATION_JSON: str = os.getenv("SENTINEL_DETECTOR_CALIBRATION_JSON", "")

    @property
    def admin_infra_hostnames_list(self) -> List[str]:
        return [h.strip().lower() for h in self.ADMIN_INFRA_HOSTNAMES.replace(";", ",").split(",") if h.strip()]

    @property
    def admin_infra_ips_list(self) -> List[str]:
        return [h.strip() for h in self.ADMIN_INFRA_IPS.replace(";", ",").split(",") if h.strip()]


# Create settings instance with validation logging
settings = Settings()

# Debug: log comprehensive API key and configuration status
import logging
_config_logger = logging.getLogger(__name__)

def _mask_key(key: str, show_chars: int = 6) -> str:
    """Mask sensitive keys for logging"""
    key = str(key or "").strip()
    if not key or len(key) <= show_chars:
        return "NOT_SET" if not key else f"SHORT({len(key)})"
    return key[:show_chars] + "*" * (len(key) - show_chars)

threat_key_count = sum(
    bool(v)
    for v in [
        settings.VIRUSTOTAL_API_KEY,
        settings.ABUSEIPDB_API_KEY,
        settings.SHODAN_API_KEY,
        settings.HYBRIDANALYSIS_API_KEY,
        settings.URLSCAN_API_KEY,
    ]
)
gemini_keys_count = len(settings.gemini_api_keys_list)
openai_keys_count = len(settings.openai_api_keys_list)

if os.getenv("SENTINEL_CONFIG_SUMMARY_LOGGED") != "1":
    _config_logger.info(
        "SENTINEL-AI config loaded | env=%s | debug=%s | external_apis=%s",
        ENV_FILE,
        settings.DEBUG,
        settings.EXTERNAL_APIS_ENABLED,
    )
    _config_logger.info(
        "Config summary | threat_keys=%s/5 | gemini_keys=%s | openai_keys=%s | model=%s",
        threat_key_count,
        gemini_keys_count,
        openai_keys_count,
        settings.OPENAI_MODEL,
    )
    os.environ["SENTINEL_CONFIG_SUMMARY_LOGGED"] = "1"
