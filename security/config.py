# security/config.py
from dataclasses import dataclass

@dataclass
class SecurityConfig:
    # 기능 ON/OFF
    enable_url_scan: bool = True
    enable_file_scan: bool = True
    enable_spam_detection: bool = True
    enable_clamav: bool = True
    enable_yara: bool = True
    enable_rabbitmq: bool = True
    enable_sqlite_log: bool = True
    enable_safe_browsing: bool = True

    #이 밑으로는 환경에 맞게 값을 넣어주면 됩니다.

    # 캐시
    url_cache_size: int = 512
    file_cache_size: int = 256

    # SQLite
    sqlite_path: str = "security_logs.db"

    # RabbitMQ
    rabbitmq_url: str = "amqp://guest:guest@localhost/"

    # ClamAV (clamd)
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310

    # YARA
    yara_rules_path="./yara_rules"  # .yar 파일들 위치

    # Google Safe Browsing
    safe_browsing_api_key: str | None = None
    safe_browsing_endpoint: str = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


