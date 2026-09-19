"""
CSRF Protection for PyOVMS

This module provides Cross-Site Request Forgery (CSRF) protection for form submissions.
Uses itsdangerous for token generation and validation.
"""

import hmac
import secrets
from typing import Optional
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import Request, HTTPException, status
import logging

from app.config import settings
from app.utils.i18n_markers import N_

logger = logging.getLogger(__name__)


# The details below travel two ways: an API caller gets them as the JSON body of a
# 403, where English is correct, and a UI route catches the exception and puts the
# text in `?error_message=` for the next page to display, where it is the one
# English line on an otherwise translated page. Translating at the raise site would
# also mean resolving a locale in a function that has no template context, so the
# strings are only *marked* (N_, see app/utils/i18n_markers.py) and the UI routes
# translate them with `_(str(e.detail))` at the point of display.


# Initialize serializer with JWT secret (reusing existing secret)
csrf_serializer = URLSafeTimedSerializer(settings.SECRET_KEY_JWT, salt="csrf-token")

# Token expiration in seconds - 8 hours, independent of JWT session length
CSRF_TOKEN_EXPIRATION = 8 * 60 * 60

# A token past this age is handed a replacement by /csrf-token/refresh instead of being
# returned unchanged. Renewing only *after* CSRF_TOKEN_EXPIRATION left a window as long
# as the poll interval in which every open form carried a token the server would already
# reject -- the user saw "Invalid or expired CSRF token" on a page that had been sitting
# there quietly refreshing itself.
CSRF_TOKEN_RENEW_AFTER = CSRF_TOKEN_EXPIRATION // 2


def generate_csrf_token() -> str:
    """Generate a new CSRF token."""
    random_data = secrets.token_hex(32)
    return csrf_serializer.dumps(random_data)


def validate_csrf_token(token: str, max_age: int = CSRF_TOKEN_EXPIRATION) -> bool:
    """
    Validate a CSRF token.

    Args:
        token: The CSRF token to validate
        max_age: Maximum age of token in seconds

    Returns:
        True if token is valid, False otherwise
    """
    try:
        csrf_serializer.loads(token, max_age=max_age)
        return True
    except (BadSignature, SignatureExpired) as e:
        logger.warning(f"Invalid CSRF token: {e}")
        return False


def csrf_token_needs_renewal(token: str, renew_after: int = CSRF_TOKEN_RENEW_AFTER) -> bool:
    """
    True if `token` is older than `renew_after` seconds (or otherwise unusable).

    Deliberately quiet: this is asked on every refresh poll about tokens that are still
    perfectly valid, so it must not log the way validate_csrf_token() does.
    """
    try:
        csrf_serializer.loads(token, max_age=renew_after)
        return False
    except (BadSignature, SignatureExpired):
        return True


def get_csrf_token(request: Request) -> str:
    """
    Get or create CSRF token for the current session.

    Args:
        request: FastAPI request object

    Returns:
        CSRF token string
    """
    existing = request.session.get("csrf_token")
    if not existing or not validate_csrf_token(existing):
        request.session["csrf_token"] = generate_csrf_token()
    return request.session["csrf_token"]


def verify_csrf_token(request: Request, form_token: Optional[str] = None, rotate_token: bool = True) -> None:
    """
    Verify CSRF token from form submission.

    Accepts either the current session token or the immediately previous one so that
    multiple open tabs and the browser back-button still work after a rotation.

    Raises:
        HTTPException: If token is missing or invalid
    """
    # Idempotent per request: only verify once, but honour a rotation request
    if getattr(request.state, "csrf_verified", False):
        if rotate_token and not getattr(request.state, "csrf_rotated", False):
            _rotate(request)
        return

    session_token = request.session.get("csrf_token")

    if not session_token:
        logger.warning(f"CSRF token missing from session for endpoint {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=N_("CSRF token missing from session. Please refresh the page.")
        )

    if not form_token:
        logger.warning(f"CSRF token missing from form/data for endpoint {request.url.path}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=N_("CSRF token missing from form submission.")
        )

    if not validate_csrf_token(form_token):
        logger.warning(f"CSRF token validation failed for endpoint {request.url.path}")
        _rotate(request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=N_("Invalid or expired CSRF token. Please try again.")
        )

    prev_token = request.session.get("csrf_token_prev")
    current_matches = hmac.compare_digest(session_token, form_token)
    prev_matches = prev_token is not None and hmac.compare_digest(prev_token, form_token)

    if not current_matches and not prev_matches:
        logger.warning(f"CSRF token mismatch for endpoint {request.url.path}. Session: {session_token[:8]}..., Form: {form_token[:8]}...")
        _rotate(request)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=N_("CSRF token mismatch. Please try again.")
        )

    request.state.csrf_verified = True

    if rotate_token:
        _rotate(request)
    else:
        request.state.csrf_rotated = False


def rotate_csrf_token(request: Request) -> None:
    """
    Public wrapper around the rotation, for callers that verify without rotating.

    Used by flows that may be legitimately retried against the same rendered form
    (2FA code entry): rotating on a failed attempt would invalidate the token the
    client still holds and turn a mistyped code into "CSRF token mismatch, start
    over". Those callers verify with rotate_token=False and rotate here once the
    step actually succeeds.
    """
    _rotate(request)


def _rotate(request: Request) -> None:
    """Rotate the session CSRF token, keeping the old one as fallback for one more request."""
    current = request.session.get("csrf_token")
    if current:
        request.session["csrf_token_prev"] = current
    request.session["csrf_token"] = generate_csrf_token()
    request.state.csrf_rotated = True
