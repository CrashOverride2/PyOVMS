"""
CSRF Protection Dependency for FastAPI

This module provides a dependency to enforce CSRF protection on mutating routes.
"""

from fastapi import Request, HTTPException, status, Depends
from app.csrf_protection import verify_csrf_token
from app.dependencies import get_client_ip
from app.security_manager import security_manager
import logging

logger = logging.getLogger(__name__)

async def csrf_protect(
    request: Request,
    client_ip: str = Depends(get_client_ip),
):
    """
    Dependency to verify CSRF token for POST, PUT, DELETE, PATCH requests.
    Only applies to requests with a session (UI routes).
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # Skip CSRF check for JSON requests.
        # 1. JSON requests (like WebAuthn) usually have the CSRF token in the JSON body,
        #    which this dependency cannot easily access without consuming the body.
        # 2. These handlers in our app manually call verify_csrf_token(request, data.csrf_token).
        # 3. Cross-origin JSON requests with Content-Type: application/json are already
        #    protected by browser CORS preflights.
        content_type = request.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            logger.debug(f"Skipping global CSRF check for JSON request to {request.url.path}")
            return True

        # We only want to enforce this on UI routes that use session cookies.
        # API routes usually use API keys or Bearer tokens and are naturally 
        # protected against CSRF if they don't use cookies for auth.
        has_session = "session" in request.cookies
        has_token = "access_token" in request.cookies or "__Host-access_token" in request.cookies
        
        if has_session or has_token:
            # Manually read form data to avoid FastAPI's 422 error when mixing JSON and Form bodies.
            # Starlette caches the form data, so handlers using Form(...) will still work.
            try:
                form_data = await request.form()
                csrf_token = form_data.get("csrf_token")
            except Exception as e:
                logger.warning(f"Failed to read form data for CSRF check: {e}")
                csrf_token = None

            try:
                # Note: verify_csrf_token is now idempotent per-request.
                # We use rotate_token=False here so that the global dependency
                # doesn't force a rotation if the specific handler doesn't want it.
                verify_csrf_token(request, csrf_token, rotate_token=False)
            except HTTPException:
                security_manager.record_failure(client_ip, "api_general")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token validation failed. Please refresh the page and try again."
                )
    return True
