# This file allows the charge_logger service to reuse the main application's
# user authentication dependency for securing its API endpoints.
from typing import Optional
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.dependencies import get_user_from_api_key, _get_access_token
from app.models.db import User as OvmsUser
from app.database import get_db
from app import security


async def get_user_from_request_cookie_fully_authenticated(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[OvmsUser]:
    """
    Try cookie authentication while enforcing MFA completion.
    Returns None for missing/invalid/partially authenticated cookies.
    """
    token_from_cookie = _get_access_token(request)
    if not token_from_cookie:
        return None
    try:
        return await security.decode_jwt_and_get_user(token=token_from_cookie, db=db, ignore_mfa_check=False)
    except HTTPException:
        return None
    except Exception:
        return None


async def get_current_user(
    user_from_api_key: Optional[OvmsUser] = Depends(get_user_from_api_key),
    user_from_cookie: Optional[OvmsUser] = Depends(get_user_from_request_cookie_fully_authenticated),
    db: Session = Depends(get_db)
) -> OvmsUser:
    """
    Attempts to authenticate the user via API key first, then falls back to cookie.
    This allows the charge logger API to be accessed both programmatically and via the web UI.
    """
    user = user_from_api_key or user_from_cookie

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid API key or login session.",
            headers={"WWW-Authenticate": "APIKey, Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    return user
