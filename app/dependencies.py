from typing import Optional
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, status, Security, Request
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

from app import crud
from app.models import db as models_db
from app.database import get_db
from app import security
from app.security_manager import security_manager
from app.config import settings
import logging

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

_SECURE_COOKIE = "__Host-access_token"
_LEGACY_COOKIE = "access_token"


def _request_is_secure(request: Request) -> bool:
    """
    Whether this deployment serves the session cookie with the __Host- prefix.

    Deliberately the same expression the login routes use when they *set* the cookie
    (ui/auth.py, ui/webauthn.py), so reader and writer cannot drift apart and log
    everyone out.
    """
    return settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"


def _get_access_token(request: Request) -> Optional[str]:
    """
    The session token, preferring the __Host- prefixed cookie.

    The unprefixed name is accepted only on a plain-HTTP deployment — the local test
    server, where the prefix cannot be used at all. Accepting it over HTTPS as well
    handed back exactly what the prefix buys: a __Host- cookie can only be set by the
    exact host over a secure connection, so a sibling subdomain cannot write one. The
    unprefixed name has no such rule, so any subdomain (one stale CNAME, one XSS on a
    neighbouring host) could set `access_token` for the parent domain and fix a visitor
    into a session of the attacker's choosing — the victim then files their vehicle,
    their location history and their API keys into someone else's account. Forging a
    token was never possible; steering the browser to a valid one was.
    """
    token = request.cookies.get(_SECURE_COOKIE)
    if token:
        return token
    if _request_is_secure(request):
        return None
    return request.cookies.get(_LEGACY_COOKIE)


async def get_client_ip(request: Request) -> str:
    """
    Retrieves the client's IP address.

    Do NOT re-parse X-Forwarded-For here. uvicorn's ProxyHeadersMiddleware
    (enabled in run.py via proxy_headers=True + forwarded_allow_ips) already
    rewrote request.client to the correct address by peeling *trusted* proxies
    off the right of the chain. Taking the leftmost XFF entry ourselves would
    hand the client full control over its own rate-limit identity: it could
    rotate a spoofed header to bypass every block, or name a victim IP and fail
    auth until that victim is locked out.

    This is only sound while FORWARDED_ALLOW_IPS is a concrete host/network
    list. With "*" uvicorn also falls back to the leftmost entry, which is why
    bootstrap._check_proxy_configuration() refuses to start on that value.
    """
    return request.client.host if request.client else "unknown"

async def get_user_from_api_key(
    api_key_value: Optional[str] = Security(api_key_header),
    client_ip: str = Depends(get_client_ip),
    db: Session = Depends(get_db)
) -> Optional[models_db.User]:
    if not api_key_value:
        return None
    
    if security_manager.is_blocked(client_ip):
        return None
    
    db_api_key = crud.apikey.get_api_key_by_raw_key(db, api_key_value)

    # An unknown key is a guess: count it towards the brute-force limit.
    if not db_api_key:
        security_manager.record_failure(client_ip, 'apikey')
        return None

    # A key that is merely expired or deactivated is NOT evidence of guessing — the
    # caller demonstrably held a genuine key, which no amount of brute force produces.
    # Counting it meant a client still retrying with a lapsed key (a phone whose app
    # polls in the background) locked its own address out after ten attempts, and the
    # user then could not even reach the login page to re-provision. Rejecting it
    # without recording a failure loses nothing: the response is still 401, and an
    # attacker gains no information they did not already have.
    if not db_api_key.is_active:
        return None

    expires_at = db_api_key.expires_at
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            return None

    crud.apikey.update_api_key_last_used(db, db_api_key)
    
    return db_api_key.user if db_api_key.user else None

async def require_api_key_user(
    user: Optional[models_db.User] = Depends(get_user_from_api_key)
) -> models_db.User:
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
            headers={"WWW-Authenticate": "APIKey"},
        )
    return user

async def require_active_api_user(
    user: models_db.User = Depends(require_api_key_user)
) -> models_db.User:
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")
    return user

async def require_admin_api_user(
    user: models_db.User = Depends(require_active_api_user)
) -> models_db.User:
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key does not grant administrative privileges"
        )
    return user

async def get_user_from_request_cookie(
    request: Request, db: Session = Depends(get_db)
) -> Optional[models_db.User]:
    """
    Tries to get a user from the access_token cookie. This does NOT enforce 2FA completion,
    making it suitable for pages that can be accessed before the 2FA step (like the 2FA form itself).
    """
    token_from_cookie = _get_access_token(request)
    if not token_from_cookie:
        return None
    try:
        user = await security.decode_jwt_and_get_user(token=token_from_cookie, db=db, ignore_mfa_check=True)
        return user
    except HTTPException:
        return None
    except Exception as e:
        logger.error(f"Error getting user from cookie: {e}")
        return None

async def require_current_user_from_cookie(
    request: Request,
    user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
) -> models_db.User:
    """Requires a valid, active user from a cookie, but does not check for 2FA completion."""
    login_url = str(request.url_for('ui_login_form'))

    if not user:
        redirect_url = login_url + "?error_message=Not authenticated. Please login."
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": redirect_url})
    
    if not user.is_active:
        redirect_url = login_url + "?error_message=Your account is inactive."
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": redirect_url})
    
    return user

async def require_current_user_from_cookie_fully_authenticated(
    request: Request,
    user: Optional[models_db.User] = Depends(get_user_from_request_cookie),
    db: Session = Depends(get_db)
) -> models_db.User:
    """
    Requires a valid, active, and fully authenticated (2FA passed) user from a cookie.
    This is the primary dependency for protecting most UI pages.
    """
    login_url = str(request.url_for('ui_login_form'))
    
    if not user:
        redirect_url = login_url + "?error_message=Not authenticated. Please login."
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": redirect_url})

    if not user.is_active:
        redirect_url = login_url + "?error_message=Your account is inactive."
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": redirect_url})
    
    try:
        token_value = _get_access_token(request)
        await security.decode_jwt_and_get_user(token=token_value, db=db, ignore_mfa_check=False)
    except HTTPException as e:
        if e.status_code == 401:
             logger.warning(f"User '{user.username}' accessed a protected page with a JWT lacking MFA completion. Redirecting to 2FA entry.")
             totp_url = str(request.url_for('ui_login_totp_form'))
             raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": totp_url})
        raise e

    return user

async def require_admin_user_from_cookie(
    request: Request,
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
) -> models_db.User:
    """Requires the current user from a cookie to be an administrator."""
    if not current_user.is_admin:
        dashboard_url = str(request.url_for('ui_dashboard'))
        redirect_url = dashboard_url + "?error_message=You do not have permission to access this page."
        raise HTTPException(status_code=status.HTTP_307_TEMPORARY_REDIRECT, headers={"Location": redirect_url})
    return current_user


async def require_admin_user_from_cookie_or_api(
    request: Request,
    db: Session = Depends(get_db),
    api_key_value: Optional[str] = Security(api_key_header),
    client_ip: str = Depends(get_client_ip)
) -> models_db.User:
    """
    Requires admin user authenticated either via cookie (for UI) or API key (for API).
    This dependency supports both authentication methods for endpoints used by both UI and API clients.
    """
    # Try API key authentication first
    if api_key_value:
        user = await get_user_from_api_key(api_key_value, client_ip, db)
        if user and user.is_active and user.is_admin:
            return user
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key or insufficient privileges"
        )

    # Try cookie authentication
    user = await get_user_from_request_cookie(request, db)
    if user and user.is_active and user.is_admin:
        # Verify 2FA completion for cookie auth
        try:
            token_value = _get_access_token(request)
            await security.decode_jwt_and_get_user(token=token_value, db=db, ignore_mfa_check=False)
            return user
        except HTTPException as e:
            if e.status_code == 401:
                logger.warning(f"Admin cookie-or-API auth: MFA not completed for '{user.username}', denying access.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Provide valid cookie session or API key.",
                headers={"WWW-Authenticate": "APIKey"}
            )

    # No valid authentication found
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide valid cookie session or API key.",
        headers={"WWW-Authenticate": "APIKey"}
    )
