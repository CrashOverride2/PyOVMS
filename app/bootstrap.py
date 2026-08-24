import logging
import logging.handlers
from pathlib import Path
import secrets
import string
import sys

from alembic.config import Config as AlembicConfig
from alembic import command as alembic_command
from fastapi.concurrency import run_in_threadpool

from app.database import SessionLocal, init_db_models_import
from app.models import api as models_api
from app.models import db as models_db
from app import crud
from app.config import settings
from app.notifications import initialize_firebase_app, initialize_apns_client
from app.services.mqtt_auth_manager import mqtt_manager
from app.mqtt_metrics_subscriber import mqtt_metrics_subscriber
from app.mqtt_notification_subscriber import mqtt_notification_subscriber
from app.mqtt_interactive_client import mqtt_interactive_client
from app.services.disposable_email_service import disposable_email_service

module_logger = logging.getLogger(__name__)

async def run_migrations():
    """Applies database migrations using Alembic."""
    module_logger.info("Attempting to apply database migrations...")
    try:
        alembic_cfg_path = "alembic.ini"
        if not Path(alembic_cfg_path).exists() and Path(__file__).parent.parent / alembic_cfg_path:
            alembic_cfg_path = str(Path(__file__).parent.parent / alembic_cfg_path)

        alembic_cfg = AlembicConfig(alembic_cfg_path)
        alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
        await run_in_threadpool(alembic_command.upgrade, alembic_cfg, "head")
        module_logger.info("Database migrations applied successfully (or already up-to-date).")
    except Exception as e:
        module_logger.error(f"Failed to apply database migrations: {e}", exc_info=True)

def _generate_compliant_password(length=16):
    """Generates a cryptographically secure password compliant with the app's validation rules."""
    lower, upper, digits, special = string.ascii_lowercase, string.ascii_uppercase, string.digits, "@$!%*?&_#"
    all_chars = lower + upper + digits + special
    # Guarantee at least one character from each required class, fill the rest randomly
    required = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits), secrets.choice(special)]
    rest = [secrets.choice(all_chars) for _ in range(length - len(required))]
    combined = required + rest
    # Shuffle using secrets-backed SystemRandom so order is also unpredictable
    secrets.SystemRandom().shuffle(combined)
    return "".join(combined)

def create_initial_admin_if_needed(db: SessionLocal):
    """Checks if any user exists, and if not, creates a first admin with random credentials."""
    if db.query(models_db.User).first():
        module_logger.info("Admin user check: At least one user already exists. No new admin created.")
        return

    new_username = f"admin_{secrets.token_hex(4)}"
    new_password = _generate_compliant_password(16)
    email = "admin@example.com"
    try:
        domain_part = settings.SERVER_BASE_URL.split('//')[-1].split(':')
        if '.' in domain_part:
            email = f"admin@{domain_part}"
    except Exception: pass

    user_in = models_api.UserCreate(
        username=new_username, password=new_password, email=email,
        full_name="Initial Administrator", is_admin=True, is_active=True
    )
    crud.user.create_user(db, user_in)

    # The generated password must never reach a file-backed handler: LOG_FILE is
    # created with the process umask (typically 0644) and keeps up to 5 rotated
    # backups, so logging it would leave the initial admin credentials readable
    # to every local account. Write it straight to stderr instead — systemd/
    # docker still capture it, but it is not persisted to disk by us.
    banner = "=" * 80
    print(banner, file=sys.stderr)
    print("NO ADMIN USER FOUND - CREATING INITIAL ADMIN", file=sys.stderr)
    print("This is a one-time setup message. Store these credentials securely.", file=sys.stderr)
    print(f"  Username: {new_username}", file=sys.stderr)
    print(f"  Password: {new_password}", file=sys.stderr)
    print("PLEASE LOG IN AND CHANGE THESE CREDENTIALS IMMEDIATELY.", file=sys.stderr)
    print(banner, file=sys.stderr, flush=True)

    # Only the fact that an admin was created goes to the regular log.
    module_logger.critical(
        "Initial administrator '%s' created. Credentials were printed to stderr only "
        "(never written to LOG_FILE). Log in and change them immediately.",
        new_username,
    )

_PLACEHOLDER_MARKERS = (
    "change_this_for_production",
    "changeme_",
    "0gXIqS9Z0kZ-Yg7tJ2eX_rU8wH6vI9nL0fA3cE1bS2k=_change_this_strong_random_key",
    "placeholder",
    "a_very_strong_mqtt_password_for_karto",
)

def _check_critical_secrets():
    """Abort startup if any critical secret is still at its placeholder value."""
    checks = {
        "SECRET_KEY_JWT": settings.SECRET_KEY_JWT,
        "SECRET_KEY_SESSION": settings.SECRET_KEY_SESSION,
        "TOTP_ENCRYPTION_KEY": settings.TOTP_ENCRYPTION_KEY,
    }
    weak = [
        name for name, value in checks.items()
        if any(marker in value for marker in _PLACEHOLDER_MARKERS)
    ]
    if weak:
        raise RuntimeError(
            f"STARTUP ABORTED: The following secrets still contain placeholder values and must be "
            f"replaced before running in production: {', '.join(weak)}. "
            f"Run via run.py to auto-generate secure values, or set them manually in .env."
        )

    # Abort if MQTT is configured but passwords are still placeholders
    if settings.MQTT_BROKER_HOST and settings.MQTT_BROKER_HOST.strip():
        mqtt_checks = {
            "MQTT_BACKEND_METRICS_SUB_PASS": settings.MQTT_BACKEND_METRICS_SUB_PASS or "",
            "MQTT_BACKEND_NOTIFY_SUB_PASS": settings.MQTT_BACKEND_NOTIFY_SUB_PASS or "",
            "MQTT_BACKEND_INTERACTIVE_PASS": settings.MQTT_BACKEND_INTERACTIVE_PASS or "",
        }
        weak_mqtt = [
            name for name, value in mqtt_checks.items()
            if any(marker in value for marker in _PLACEHOLDER_MARKERS)
        ]
        if weak_mqtt:
            raise RuntimeError(
                f"STARTUP ABORTED: MQTT is configured but the following passwords are still at "
                f"placeholder values: {', '.join(weak_mqtt)}. "
                f"Set them in .env or remove MQTT_BROKER_HOST to disable MQTT."
            )

    # Abort if Karto is enabled but its MQTT password is still a placeholder
    if settings.ENABLE_KARTO_TRIP_TRACKING:
        karto_pass = settings.KARTO_MQTT_PASSWORD or ""
        if any(marker in karto_pass for marker in _PLACEHOLDER_MARKERS):
            raise RuntimeError(
                "STARTUP ABORTED: Karto trip tracking is enabled but KARTO_MQTT_PASSWORD is still "
                "at its placeholder value. Set it in .env or set ENABLE_KARTO_TRIP_TRACKING=false."
            )


def _check_jwt_keys():
    """
    Abort startup if the session signing key is missing or malformed.

    Session tokens moved from HS256/SECRET_KEY_JWT to Ed25519 so the Karto service can
    verify them without being able to issue them. Failing here is deliberate: falling
    back to the shared symmetric secret would silently restore the very capability this
    change removes.
    """
    from app import jwt_keys

    try:
        jwt_keys.get_private_key()
        jwt_keys.get_public_key()
    except jwt_keys.JwtKeyError as exc:
        raise RuntimeError(
            f"STARTUP ABORTED: session signing key is unusable — {exc} "
            f"Generate a pair with 'python -m app.jwt_keys' and put JWT_PRIVATE_KEY and "
            f"JWT_PUBLIC_KEY in .env (run.py does this automatically on first start)."
        ) from exc

    # A mismatched pair would mint tokens the server itself cannot verify: every login
    # would appear to succeed and then immediately fail.
    #
    # This must compare against the key *derived from the private key*. Using
    # public_key_b64() here compared the configured value with itself — it returns
    # JWT_PUBLIC_KEY unchanged whenever that is set — so the check could never fire
    # and a mismatched pair started up cleanly. Covered by tests/test_jwt_keys.py.
    if settings.JWT_PUBLIC_KEY:
        derived = jwt_keys.derived_public_key_b64()
        if derived != settings.JWT_PUBLIC_KEY.strip():
            raise RuntimeError(
                "STARTUP ABORTED: JWT_PUBLIC_KEY does not belong to JWT_PRIVATE_KEY. "
                "Sessions would be signed with one key and verified with another, so every "
                f"login would fail. The key matching the configured private key is: {derived}"
            )


def _check_totp_key_availability():
    """
    Warn loudly if any 2FA user's secret was encrypted with a key we cannot load.

    Not fatal: this is a data condition, and refusing to boot would take the whole
    server down over a handful of accounts. But it must not be silent either — the
    affected users simply cannot log in, and without this the first sign is a
    support request.
    """
    from app.database import SessionLocal
    from app.totp_key_rotation import find_users_with_unavailable_keys

    db = SessionLocal()
    try:
        affected = find_users_with_unavailable_keys(db)
    except Exception as exc:
        module_logger.warning(f"Could not verify TOTP key availability: {exc}")
        return
    finally:
        db.close()

    if affected:
        module_logger.critical(
            "%d user(s) have a TOTP secret encrypted with an unavailable key version and "
            "CANNOT complete 2FA login: %s. This normally means TOTP_ENCRYPTION_KEY_V2 was "
            "removed from .env after a key rotation. Restore that key.",
            len(affected), ", ".join(sorted(affected)),
        )


def _check_proxy_configuration():
    """
    Abort startup if FORWARDED_ALLOW_IPS trusts every peer.

    get_client_ip() relies on uvicorn having already resolved request.client
    from X-Forwarded-For. uvicorn only peels trusted proxies off the right of
    the chain while the trust list is concrete; with "*" it falls back to the
    leftmost entry, which is fully client-controlled. That would make every
    IP-based rate limit and block both bypassable and weaponizable against
    arbitrary victims, so refuse to run in that configuration.
    """
    entries = {entry.strip() for entry in settings.FORWARDED_ALLOW_IPS.split(",")}
    if "*" in entries:
        raise RuntimeError(
            "STARTUP ABORTED: FORWARDED_ALLOW_IPS is set to '*', which makes the client IP "
            "attacker-controlled and defeats all IP rate limiting and blocking. Set it to the "
            "concrete address(es) or network(s) of your reverse proxy, e.g. "
            "FORWARDED_ALLOW_IPS=\"127.0.0.1\"."
        )


async def initialize_services():
    """Initializes and connects all external services."""
    module_logger.info("Initializing services...")
    _check_critical_secrets()
    _check_jwt_keys()
    _check_proxy_configuration()
    _check_totp_key_availability()
    init_db_models_import()
    initialize_firebase_app()
    initialize_apns_client()

    db = SessionLocal()
    try:
        await run_in_threadpool(create_initial_admin_if_needed, db)
        await run_in_threadpool(disposable_email_service.warm_cache, db)
        
        if settings.MQTT_BROKER_HOST and settings.MQTT_BROKER_HOST.strip():
            module_logger.info("MQTT integration is enabled. Connecting backend clients.")
            if settings.MQTT_BACKEND_METRICS_SUB_USER and settings.MQTT_BACKEND_METRICS_SUB_PASS:
                mqtt_metrics_subscriber.connect(username=settings.MQTT_BACKEND_METRICS_SUB_USER, password=settings.MQTT_BACKEND_METRICS_SUB_PASS)
            if settings.MQTT_BACKEND_NOTIFY_SUB_USER and settings.MQTT_BACKEND_NOTIFY_SUB_PASS:
                mqtt_notification_subscriber.connect(username=settings.MQTT_BACKEND_NOTIFY_SUB_USER, password=settings.MQTT_BACKEND_NOTIFY_SUB_PASS)
            if settings.MQTT_BACKEND_INTERACTIVE_USER and settings.MQTT_BACKEND_INTERACTIVE_PASS:
                mqtt_interactive_client.connect(username=settings.MQTT_BACKEND_INTERACTIVE_USER, password=settings.MQTT_BACKEND_INTERACTIVE_PASS)
            
            if mqtt_manager.is_enabled():
                await run_in_threadpool(mqtt_manager.sync_all_from_db, db)
        else:
            module_logger.info("MQTT integration is disabled (MQTT_BROKER_HOST not set).")
    finally:
        db.close()
