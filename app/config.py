from pydantic_settings import BaseSettings
from pydantic import field_validator
from pathlib import Path
import os
from typing import Optional, List, Union
import logging

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./ovms_py.db"

    # Database connection pooling. Ignored for SQLite, which uses SQLAlchemy's
    # SingletonThreadPool/NullPool and rejects these arguments.
    #
    # The numbers match Karto's, deliberately: both services normally point at the same
    # PostgreSQL server, so the ceiling that matters is the sum of the two pools against
    # that server's max_connections. Raising one side alone is how you find out what
    # happens when the other cannot get a connection.
    #
    # pool_timeout is the reason there is a limit at all: without it a caller that cannot
    # get a connection waits forever, so an overloaded database turns into a pile of
    # blocked requests instead of a visible error. The 2s broadcaster and the V2 TCP
    # servers share this event loop, so "waits forever" means the whole server.
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT_SECONDS: int = 30


    NTFY_SERVER: Optional[str] = "https://ntfy.sh" 
    NTFY_DEFAULT_TOPIC: str = "ovms_alerts_python"
    NTFY_AUTH_METHOD: Optional[str] = None 
    NTFY_AUTH_TOKEN: Optional[str] = None 
    NTFY_AUTH_USER: Optional[str] = None 
    NTFY_AUTH_PASSWORD: Optional[str] = None 
    NTFY_AUTH_QUERY_PARAM_NAME: str = "token" 

    EMAIL_HOST: Optional[str] = None
    EMAIL_PORT: int = 587
    EMAIL_USE_TLS: bool = True
    EMAIL_USE_SSL: bool = False
    EMAIL_USERNAME: Optional[str] = None
    EMAIL_PASSWORD: Optional[str] = None
    EMAIL_SENDER: Optional[str] = None

    # Outbound mail queue (app/notifications/email_queue.py). The worker count is also
    # the ceiling on concurrent SMTP connections this server opens, which is the number
    # providers care about.
    EMAIL_QUEUE_WORKERS: int = 2
    EMAIL_QUEUE_MAX_SIZE: int = 1000
    EMAIL_QUEUE_MAX_ATTEMPTS: int = 5

    # --- Notification throughput -------------------------------------------------
    #
    # Every queue in this path is bounded, and every bound is here rather than hard-coded,
    # because the right value depends on the fleet size and these are the knobs to reach
    # for when notifications start arriving late.
    #
    # NOTIFY_DISPATCH_* is the stage between the MQTT network thread and the fan-out: a
    # worker holds a database session only long enough to build the plan. NOTIFY_FANOUT_
    # WORKERS is the number of outbound push requests in flight at once across the whole
    # server — it needs to cover the fleet, not one vehicle, since a worker is held for
    # one request now that retries are deferred rather than slept through.
    #
    # NOTIFY_DATA_* is the history-record path (`notify/data`). One worker on purpose:
    # records for a vehicle must be stored in the order they arrived, and the queue is
    # deep because a module that has been asleep flushes its whole buffer at once. It
    # applies back-pressure instead of dropping — the records are data, not alerts.
    NOTIFY_DISPATCH_WORKERS: int = 8
    NOTIFY_DISPATCH_QUEUE_SIZE: int = 2000
    NOTIFY_FANOUT_WORKERS: int = 32
    NOTIFY_DATA_QUEUE_SIZE: int = 20000

    # Sustained rate per vehicle, and how many notifications may arrive back-to-back
    # before it applies. A single event on a module routinely produces two or three
    # messages (charge stopped, charge complete, range); a burst of 1 delivered the
    # first and discarded the rest.
    NOTIFY_RATE_LIMIT_INTERVAL_SECONDS: float = 10.0
    NOTIFY_RATE_LIMIT_BURST: int = 4

    FCM_CREDENTIALS_PATH: Optional[str] = None 

    APNS_AUTH_KEY_PATH: Optional[str] = None 
    APNS_KEY_ID: Optional[str] = None 
    APNS_TEAM_ID: Optional[str] = None 
    APNS_TOPIC: Optional[str] = None 
    APNS_SERVER_MODE: str = "production" 
    APNS_DELIVERY_METHOD: str = "apns" 

    @field_validator('APNS_DELIVERY_METHOD')
    @classmethod
    def validate_apns_delivery_method(cls, v: str) -> str:
        method = v.lower()
        if method not in ['apns', 'fcm']:
            raise ValueError('APNS_DELIVERY_METHOD must be either "apns" or "fcm"')
        return method

    ALLOW_FCM_TOKEN_FROM_V2: bool = True
    ALLOW_APNS_TOKEN_FROM_V2: bool = False

    SERVER_HOST: str = "0.0.0.0"
    TCP_PORT: int = 6867
    TCP_SSL_PORT: int = 6870
    HTTP_PORT: int = 8000 
    SERVER_VERSION: str = "2.3.3" 
    SERVER_BASE_URL: str = "http://localhost:8000"

    SSL_CERT_FILE: Optional[str] = "cert.pem"
    SSL_KEY_FILE: Optional[str] = "key.pem"

    TIMEOUT_CAR_IDLE: int = 960 
    TIMEOUT_APP_IDLE: int = 1200 
    TIMEOUT_TCP_INITIAL_AUTH: int = 60
    TIMEOUT_CHARGE_IDLE: int = 1800
    TCP_IDLE_CHECK_INTERVAL: int = 60

    TCP_KEEPIDLE: int = 240
    TCP_KEEPINTVL: int = 240
    TCP_KEEPCNT: int = 9

    TCP_SERVER_PING_INTERVAL: int = 60

    LOG_LEVEL: str = "INFO"
    LOG_HISTORY_DAYS: int = 7 
    LOG_FILE: Optional[str] = "pyovms_control.log"
    DEBUG_TCP_PACKETS: bool = False

    # Now used only to sign CSRF tokens. Session JWTs moved to the Ed25519 key pair
    # below; this value is purely local and must not be shared with another service.
    SECRET_KEY_JWT: str = "another_super_secret_key_for_jwt_change_this_for_production"
    SECRET_KEY_SESSION: str = "another_super_secret_key_for_session_change_this_for_production"

    # Session token signing. base64 of the raw 32-byte Ed25519 values; run.py generates
    # them on first start. Only JWT_PUBLIC_KEY is copied to the Karto service — it needs
    # to verify tokens, never to issue them.
    JWT_PRIVATE_KEY: Optional[str] = None
    JWT_PUBLIC_KEY: Optional[str] = None

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60  # 1 hour

    ALLOW_USER_REGISTRATION: bool = False
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_TOKEN_EXPIRE_HOURS: int = 1
    SEND_ADMIN_REGISTRATION_EMAIL: bool = True

    FORWARDED_ALLOW_IPS: str = "127.0.0.1"

    # Force secure cookies even if not detecting HTTPS (for reverse proxy setups)
    FORCE_SECURE_COOKIES: bool = True
    MAX_API_KEYS_PER_USER: int = 50

    OTP_ISSUER_NAME: str = "PyOVMS"
    TOTP_ENCRYPTION_KEY: str = "0gXIqS9Z0kZ-Yg7tJ2eX_rU8wH6vI9nL0fA3cE1bS2k=_change_this_strong_random_key"
    TOTP_ENCRYPTION_KEY_V2: Optional[str] = None  # For key rotation

    # WebAuthn/FIDO2 Configuration
    WEBAUTHN_RP_ID: str = "localhost"  # Your domain (e.g., "example.com")
    WEBAUTHN_RP_NAME: str = "PyOVMS"  # Display name for your service
    WEBAUTHN_ORIGIN: str = "http://localhost:8000"  # Full origin URL (e.g., "https://example.com")
    # Comma-separated list of trusted Android APK key-hash origins, e.g.:
    # "android:apk-key-hash:abc123,android:apk-key-hash:def456"
    WEBAUTHN_TRUSTED_ANDROID_ORIGINS: Union[List[str], str] = []

    @field_validator('WEBAUTHN_TRUSTED_ANDROID_ORIGINS', mode='before')
    @classmethod
    def assemble_android_origins(cls, v: Union[List[str], str]) -> List[str]:
        if isinstance(v, str):
            return [o.strip() for o in v.split(',') if o.strip()]
        return v

    MQTT_PASSWD_FILE: Optional[str] = None 
    MQTT_ACL_FILE: Optional[str] = None 
    MQTT_BROKER_HOST: Optional[str] = None
    MQTT_BROKER_PORT: int = 1883 
    
    MQTT_BACKEND_METRICS_SUB_USER: Optional[str] = "pyovms_metrics_sub"
    MQTT_BACKEND_METRICS_SUB_PASS: Optional[str] = "changeme_metrics_sub_password"
    MQTT_BACKEND_NOTIFY_SUB_USER: Optional[str] = "pyovms_notify_sub"
    MQTT_BACKEND_NOTIFY_SUB_PASS: Optional[str] = "changeme_notify_sub_password"
    MQTT_BACKEND_INTERACTIVE_USER: Optional[str] = "pyovms_interactive"
    MQTT_BACKEND_INTERACTIVE_PASS: Optional[str] = "changeme_interactive_password"
    MQTT_INTERACTIVE_CLIENT_ID_PREFIX: str = "term"
    
    # Target of the "Source Code" link in the page footer. PyOVMS is GPL-3.0, which
    # carries no network clause — publishing your changes is only required when you
    # DISTRIBUTE modified binaries or source, not when you merely run a modified copy
    # as a service. Pointing this at your own fork is still the courteous thing to do.
    SOURCE_CODE_URL: str = "https://github.com/CrashOverride2/PyOVMS"

    # Optional footer links. Both are instance-specific and hidden while unset, so a
    # fresh deployment never advertises somebody else's firmware mirror or donation page.
    FIRMWARE_REPO_URL: Optional[str] = None
    DONATION_URL: Optional[str] = None

    SUPPORTED_LOCALES: Union[List[str], str] = ["en", "de", "fr", "es"]
    BABEL_DEFAULT_LOCALE: str = "en"
    BABEL_TRANSLATION_DIRECTORIES: str = "app/translations" 
    BABEL_LANG_COOKIE_NAME: str = "Babel-Locale"

    @field_validator('SUPPORTED_LOCALES', mode='before')
    @classmethod
    def assemble_supported_locales(cls, v: Union[List[str], str]) -> List[str]:
        if isinstance(v, str):
            return [lang.strip() for lang in v.split(',') if lang.strip()]
        return v

    # --- Karto Trip Tracking Integration (Optional) ---
    ENABLE_KARTO_TRIP_TRACKING: bool = False
    KARTO_MQTT_USER: Optional[str] = "karto_service_user"
    KARTO_MQTT_PASSWORD: Optional[str] = "a_very_strong_mqtt_password_for_karto"

    # --- Protomaps Integration (Optional) ---
    PROTOMAPS_URL: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'
        if not Path(".env").exists() and Path(__file__).resolve().parent.parent / ".env":
            env_file = str(Path(__file__).resolve().parent.parent / ".env")
        elif not Path(".env").exists() and os.getenv("ENV_FILE_PATH"):
             env_file = os.getenv("ENV_FILE_PATH")

settings = Settings()

logger.info(f"Loaded SUPPORTED_LOCALES: {settings.SUPPORTED_LOCALES}")

def get_settings() -> Settings:
    """Get application settings instance."""
    return settings
