# security/config.py
import os
from dataclasses import dataclass


def _env_bool(name: str, default: bool) -> bool:
    """
    환경변수에서 불리언 값을 읽어온다.
    - "1", "true", "yes", "y", "on" (대소문자 무시) → True
    - 그 외 / 미설정 → default
    """
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes", "y", "on")


@dataclass
class SecurityConfig:
    # ===== 기능 ON/OFF =====
    enable_url_scan: bool = _env_bool("ENABLE_URL_SCAN", True)
    enable_file_scan: bool = _env_bool("ENABLE_FILE_SCAN", True)
    enable_spam_detection: bool = _env_bool("ENABLE_SPAM_DETECTION", True)

    enable_clamav: bool = _env_bool("CLAMAV_ENABLED", False)
    enable_yara: bool = _env_bool("YARA_ENABLED", False)
    enable_rabbitmq: bool = _env_bool("RABBITMQ_ENABLED", False)
    enable_sqlite_log: bool = _env_bool("ENABLE_SQLITE_LOG", True)
    enable_safe_browsing: bool = _env_bool("SAFE_BROWSING_ENABLED", False)

    # ===== 캐시 크기 =====
    url_cache_size: int = int(os.getenv("URL_CACHE_SIZE", "512"))
    file_cache_size: int = int(os.getenv("FILE_CACHE_SIZE", "256"))

    # ===== SQLite =====
    # 기본값: 현재 작업 디렉토리에 security_logs.db 파일 생성
    sqlite_path: str = os.getenv("SQLITE_PATH", "security_logs.db")

    # ===== RabbitMQ =====
    # GCP / Docker 환경에 맞게 RABBITMQ_URL 환경변수를 설정해 주면 됨.
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")

    # ===== ClamAV (clamd) =====
    clamav_host: str = os.getenv("CLAMAV_HOST", "127.0.0.1")
    clamav_port: int = int(os.getenv("CLAMAV_PORT", "3310"))

    # ===== YARA =====
    yara_rules_path: str = os.getenv("YARA_RULES_PATH", "./yara_rules")

    # ===== Google Safe Browsing =====
    # SAFE_BROWSING_API_KEY 를 .env / 환경변수에 넣어주면 활성화됨.
    safe_browsing_api_key: str | None = os.getenv("SAFE_BROWSING_API_KEY")
    safe_browsing_endpoint: str = os.getenv(
        "SAFE_BROWSING_ENDPOINT",
        "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    )
