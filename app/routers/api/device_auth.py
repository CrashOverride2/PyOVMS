"""
Device provisioning for the OVMS Connect App
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app import crud, security
from app.csrf_protection import verify_csrf_token
from app.database import get_db
from app.dependencies import get_client_ip
from app.models import db as models_db
from app.security_events import SecurityEventType, security_event_logger
from app.security_manager import security_manager
from app.utils.step_up import has_recent_reauth
from app.utils.timestamps import UtcDatetime
from app.utils.two_factor import (
    SecondFactor,
    password_login_is_disabled,
    required_second_factor,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Device Provisioning"])

# A provisioned key expires this long after it was last *used*, not after it was
# issued — crud.apikey.slide_device_key_expiry() pushes it out on every authenticated
# request. An indefinite key is the wrong default for a device that can be lost, but a
# fixed lifetime would break an app that is set up once and then simply works: after
# six months it would stop authenticating and demand password and 2FA again. Sliding
# keeps both properties.
DEVICE_KEY_NAME_PREFIX = crud.apikey.DEVICE_KEY_NAME_PREFIX

# Distinguishable machine-readable reasons. The app switches on these, so they are
# part of the contract and must not be reworded casually.
REASON_INVALID_CREDENTIALS = "invalid_credentials"
REASON_TOTP_REQUIRED = "totp_required"
REASON_TOTP_INVALID = "totp_invalid"
REASON_USE_WEB_FLOW = "use_web_flow"
REASON_RATE_LIMITED = "rate_limited"
REASON_NOT_AUTHENTICATED = "not_authenticated"
REASON_CSRF_INVALID = "csrf_invalid"
REASON_REAUTH_REQUIRED = "reauth_required"
REASON_QUOTA_EXCEEDED = "quota_exceeded"


class DeviceTokenRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)
    totp_code: Optional[str] = Field(None, min_length=6, max_length=6)
    device_name: str = Field(..., min_length=1, max_length=64)

    @field_validator("device_name")
    @classmethod
    def validate_device_name(cls, v: str) -> str:
        """
        Restrictive on purpose: this ends up in an API key name that an operator
        reads in the profile UI and that is matched on re-provisioning.
        """
        import re

        candidate = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9 ._-]+", candidate):
            raise ValueError(
                "Device name may only contain letters, digits, spaces, dots, "
                "underscores and hyphens."
            )
        return candidate


class DeviceTokenResponse(BaseModel):
    api_key: str = Field(..., description="Full API key. Returned exactly once.")
    key_prefix: str
    expires_at: Optional[UtcDatetime]
    mqtt_username: str
    mqtt_password: str


class SessionDeviceTokenRequest(BaseModel):
    """
    Body of /device-token/from-session. No credentials: the session carries the
    identity, the CSRF token proves the request was not made by a third-party page.
    """

    device_name: str = Field(..., min_length=1, max_length=64)
    csrf_token: str = Field(..., min_length=1)

    _validate_device_name = field_validator("device_name")(
        DeviceTokenRequest.validate_device_name.__func__
    )


class DeviceTokenError(BaseModel):
    reason: str
    detail: str


def _error(status_code: int, reason: str, detail: str):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content={"reason": reason, "detail": detail})


def _log_event(db: Session, event_type: SecurityEventType, **kwargs) -> None:
    try:
        security_event_logger.log_event(db=db, event_type=event_type, **kwargs)
    except Exception as e:  # logging must never break authentication
        logger.warning(f"Security event logging failed ({event_type}): {e}")


def _requires_web_flow(db: Session, user: models_db.User) -> bool:
    """
    True if this account's second factor cannot be satisfied over a JSON request.

    WebAuthn needs an interactive challenge/response with the authenticator, which
    this endpoint has no way to carry. Accepting TOTP instead would be a downgrade
    for users who have both configured, so those accounts are refused here and fall
    back to the web flow in the app, which can drive the authenticator.

    The ranking itself comes from app.utils.two_factor so this endpoint, the UI login
    and the TOTP submit handler cannot disagree about which factor an account needs.
    """
    return required_second_factor(db, user) == SecondFactor.WEBAUTHN


@router.post(
    "/device-token",
    response_model=DeviceTokenResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {"model": DeviceTokenError, "description": "Credentials rejected, or 2FA needed"},
        403: {"model": DeviceTokenError, "description": "This account must use the web login flow"},
        429: {"model": DeviceTokenError, "description": "Too many attempts from this address"},
    },
    name="api_create_device_token",
)
def create_device_token(
    request: Request,
    payload: DeviceTokenRequest,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
):
    """
    Exchange username, password and (if enabled) a TOTP code for a device API key.

    Replaces the app's previous seven-step scrape of the web UI. The returned key is
    also the MQTT password for this device.

    Accounts whose second factor is a security key cannot be served here — they use
    /device-token/from-session after completing the web login instead.
    """
    generic_error = "Invalid credentials. Please check your username and password."

    if security_manager.is_blocked(client_ip):
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, REASON_RATE_LIMITED,
                      "Too many failed attempts. Try again later.")

    # Same pre-DB check as the UI login: catches a brute force spread across many
    # source addresses, which the per-IP limit alone cannot see.
    if security_manager.is_username_blocked(payload.username):
        logger.warning(
            f"Device provisioning blocked for username '{payload.username}' "
            f"due to distributed rate limit (IP: {client_ip})"
        )
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, REASON_RATE_LIMITED,
                      "Too many failed attempts. Try again later.")

    user = crud.user.get_user_by_username(db, username=payload.username)

    # One generic response for "no such user", "wrong password" and "disabled
    # account" — anything finer grained is an account enumeration oracle.
    # verify_password_for_user() runs bcrypt even when the user does not exist, so the
    # response time does not answer what the generic message withholds.
    if not security.verify_password_for_user(user, payload.password):
        logger.warning(f"Failed device provisioning from IP {client_ip} (username enumeration prevented)")
        security_manager.record_failure(client_ip, 'login', username=payload.username)
        _log_event(db, SecurityEventType.LOGIN_FAILED, ip_address=client_ip,
                   username=payload.username,
                   details={"reason": "invalid_credentials", "method": "device_token"})
        return _error(status.HTTP_401_UNAUTHORIZED, REASON_INVALID_CREDENTIALS, generic_error)

    if not user.is_active:
        logger.warning(f"Device provisioning attempt for inactive account from IP {client_ip}")
        security_manager.record_failure(client_ip, 'login', username=payload.username)
        _log_event(db, SecurityEventType.LOGIN_FAILED, ip_address=client_ip,
                   username=payload.username,
                   details={"reason": "account_inactive", "method": "device_token"})
        return _error(status.HTTP_401_UNAUTHORIZED, REASON_INVALID_CREDENTIALS, generic_error)

    if _requires_web_flow(db, user):
        return _error(
            status.HTTP_403_FORBIDDEN, REASON_USE_WEB_FLOW,
            "This account uses a security key for two-factor authentication. "
            "Please sign in using the web login flow.",
        )

    # Mirrors the UI rule: an account that registered a passwordless key and has no
    # second factor must not be reachable by password at all.
    if password_login_is_disabled(db, user):
        return _error(
            status.HTTP_403_FORBIDDEN, REASON_USE_WEB_FLOW,
            "Password login is disabled for this account. "
            "Please sign in using passwordless login with your security key.",
        )

    if user.is_totp_enabled:
        if not payload.totp_code:
            # Not a failure: the app has not asked the user for a code yet. Deliberately
            # not counted as a failed attempt, or opening the dialog would burn the
            # rate-limit budget. Reaching this point already required a valid password.
            return _error(status.HTTP_401_UNAUTHORIZED, REASON_TOTP_REQUIRED,
                          "Two-factor authentication is required for this account.")

        decrypted_secret = crud.user.get_decrypted_totp_secret_for_user(user)
        if not decrypted_secret or not security.verify_totp_code(decrypted_secret, payload.totp_code):
            security_manager.record_failure(client_ip, 'totp', username=payload.username)
            _log_event(db, SecurityEventType.TOTP_FAILED, user_id=user.id,
                       username=user.username, ip_address=client_ip,
                       details={"reason": "invalid_code", "method": "device_token"})
            return _error(status.HTTP_401_UNAUTHORIZED, REASON_TOTP_INVALID,
                          "Invalid two-factor code.")

        _log_event(db, SecurityEventType.TOTP_SUCCESS, user_id=user.id,
                   username=user.username, ip_address=client_ip,
                   details={"method": "device_token"})

    # --- authenticated from here on -------------------------------------------------

    try:
        return _issue_device_key(db, user, payload.device_name, client_ip,
                                 method="device_token")
    except _QuotaExceeded as e:
        return _error(status.HTTP_403_FORBIDDEN, REASON_QUOTA_EXCEEDED, str(e))


class _QuotaExceeded(Exception):
    """The user is at their API key limit."""


def _issue_device_key(
    db: Session, user: models_db.User, device_name: str, client_ip: str, method: str
):
    """
    Mint (or replace) this device's key. Shared by both provisioning routes.

    Both ways in must produce the *same kind of credential* — a DEVICE key with the
    server-chosen name and the sliding expiry. That is the whole point of the
    session-based route: the web-flow fallback used to end in the ordinary
    "create an API key" form, which yields a plain user key. Those are never revoked
    by a password change or reset and never expire, so accounts using a security key
    as their second factor — the only accounts that *have* to take the web flow —
    ended up with the weakest credential of all.
    """
    key_name = f"{DEVICE_KEY_NAME_PREFIX}{device_name}"

    # Re-provisioning the same device replaces its key instead of adding another.
    # The old flow left every previous key active, so a user who re-ran setup a few
    # times accumulated valid credentials they had no way of knowing about.
    revoked = crud.apikey.delete_api_keys_by_name_for_user(db, user_id=user.id, name=key_name)
    if revoked:
        logger.info(f"Device provisioning: replaced {revoked} existing key(s) named '{key_name}'.")
        _log_event(db, SecurityEventType.API_KEY_REVOKED, user_id=user.id,
                   username=user.username, ip_address=client_ip,
                   details={"reason": "device_reprovisioned", "device": key_name, "count": revoked})

    try:
        db_api_key, plain_key = crud.apikey.create_api_key(
            db=db,
            user_id=user.id,
            name=key_name,
            expires_delta=crud.apikey.DEVICE_KEY_IDLE_VALIDITY,
            # DEVICE, not INTERNAL: the key is user-requested and counts against the
            # per-user quota exactly like one created from the profile page. What the
            # purpose adds is the server-chosen name and the sliding expiry, recorded
            # on the row itself so it cannot be inferred from the name later.
            purpose=crud.apikey.KeyPurpose.DEVICE,
        )
    except ValueError as e:
        raise _QuotaExceeded(str(e))

    crud.user.record_login(db, user)
    _log_event(db, SecurityEventType.API_KEY_CREATED, user_id=user.id,
               username=user.username, ip_address=client_ip,
               details={"key_prefix": db_api_key.key_prefix, "device": key_name,
                        "method": method})
    _log_event(db, SecurityEventType.LOGIN_SUCCESS, user_id=user.id,
               username=user.username, ip_address=client_ip,
               details={"method": method})

    logger.info(
        f"Device provisioning ({method}): issued key {db_api_key.key_prefix} for user "
        f"'{user.username}' device '{device_name}' from {client_ip}."
    )

    return DeviceTokenResponse(
        api_key=plain_key,
        key_prefix=db_api_key.key_prefix,
        expires_at=db_api_key.expires_at,
        mqtt_username=db_api_key.key_prefix,
        mqtt_password=plain_key,
    )


async def _session_user(request: Request, db: Session) -> Optional[models_db.User]:
    """
    The fully authenticated user behind the session cookie, or None.

    Deliberately not require_current_user_from_cookie_fully_authenticated: that
    dependency answers a missing or half-finished session with a 307 to the login
    page, which is right for a browser and useless for a JSON client — it would
    follow the redirect and parse an HTML login form as its device key. Same checks,
    machine-readable outcome.
    """
    from app.dependencies import _get_access_token

    token = _get_access_token(request)
    if not token:
        return None
    try:
        # ignore_mfa_check defaults to False: a token minted before the second factor
        # was satisfied must not be able to mint a credential here.
        user = await security.decode_jwt_and_get_user(token=token, db=db)
    except HTTPException:
        return None
    except Exception as e:  # pragma: no cover - mirrors get_user_from_request_cookie
        logger.error(f"Device provisioning: error resolving session user: {e}")
        return None
    if not user or not user.is_active:
        return None
    return user


@router.post(
    "/device-token/from-session",
    response_model=DeviceTokenResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        401: {"model": DeviceTokenError, "description": "No usable session"},
        403: {"model": DeviceTokenError, "description": "CSRF, step-up or quota"},
    },
    name="api_create_device_token_from_session",
)
async def create_device_token_from_session(
    request: Request,
    payload: SessionDeviceTokenRequest,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
):
    """
    Issue a device key for an already authenticated browser session.

    The counterpart to /device-token for the logins that cannot be carried over a
    single JSON request. An account using a security key as its second factor is
    refused there on purpose (accepting a TOTP code instead would step around the
    stronger factor), so the app completes the interactive web login and calls this.

    Before this existed that fallback ended in POST /profile/apikeys/create — the
    ordinary "create an API key" form — and the app therefore ran on a plain user
    key: no expiry, and untouched by the revocation that a password change or reset
    performs on device keys. The accounts with the strongest second factor had the
    weakest credential.

    Three guards, all of which the plain-password route gets for free by not having a
    session at all:

    * **CSRF**, because this route *does* carry ambient authority. Without it any
      page could mint a device key — and therefore an MQTT password — for a visiting
      user.
    * **Completed 2FA**, enforced by _session_user().
    """
    if security_manager.is_blocked(client_ip):
        return _error(status.HTTP_429_TOO_MANY_REQUESTS, REASON_RATE_LIMITED,
                      "Too many failed attempts. Try again later.")

    user = await _session_user(request, db)
    if not user:
        return _error(status.HTTP_401_UNAUTHORIZED, REASON_NOT_AUTHENTICATED,
                      "No active session. Sign in first.")

    try:
        verify_csrf_token(request, payload.csrf_token)
    except HTTPException as e:
        _log_event(db, SecurityEventType.CSRF_VIOLATION, ip_address=client_ip,
                   username=user.username,
                   details={"endpoint": "device_token_from_session", "reason": e.detail})
        return _error(status.HTTP_403_FORBIDDEN, REASON_CSRF_INVALID, str(e.detail))

    # Same gate as the profile page's key creation. A session that has been sitting
    # open is not enough to mint a credential that doubles as the MQTT password.
    if not has_recent_reauth(request, user.id):
        return _error(
            status.HTTP_403_FORBIDDEN, REASON_REAUTH_REQUIRED,
            "Please sign in again before provisioning this device.",
        )

    try:
        return _issue_device_key(db, user, payload.device_name, client_ip,
                                 method="device_token_session")
    except _QuotaExceeded as e:
        return _error(status.HTTP_403_FORBIDDEN, REASON_QUOTA_EXCEEDED, str(e))
