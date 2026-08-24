"""
TOTP Key Rotation Routes

Admin interface for rotating TOTP encryption keys without requiring users to re-setup 2FA.
"""
from fastapi import APIRouter, Request, Depends, Form, status
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Dict

from app.database import get_db
from app import crud
from app.models import db as models_db
from . import templates, get_common_template_vars
from app.dependencies import require_admin_user_from_cookie
from app.totp_key_rotation import totp_key_manager
from app.csrf_protection import verify_csrf_token

router = APIRouter()


@router.get("/key-rotation", response_class=HTMLResponse, name="ui_totp_key_rotation_page")
def ui_totp_key_rotation_page_route(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    """Display TOTP key rotation management page."""
    common_vars = get_common_template_vars(request, current_admin)

    # Get statistics about current key versions
    users_with_totp = db.query(models_db.User).filter(
        models_db.User.is_totp_enabled == True
    ).all()

    version_stats: Dict[int, int] = {}
    for user in users_with_totp:
        version = getattr(user, 'totp_key_version', 1) or 1
        version_stats[version] = version_stats.get(version, 0) + 1

    # Check which key versions are available
    available_keys = list(totp_key_manager.encryption_keys.keys())

    return templates.TemplateResponse(request, "totp_key_rotation.html", {
        **common_vars,
        "page_title": "TOTP Key Rotation",
        "total_totp_users": len(users_with_totp),
        "version_stats": version_stats,
        "available_keys": available_keys,
    })


@router.post("/rotate-all", response_class=JSONResponse, name="ui_totp_rotate_all")
def ui_totp_rotate_all_route(
    request: Request,
    target_version: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    """Rotate all users' TOTP keys to the target version."""
    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "error": str(e)}
        )

    # Perform rotation
    stats = totp_key_manager.rotate_all_users(db, target_version=target_version)

    return JSONResponse(content={
        "success": True,
        "stats": stats
    })


@router.post("/rotate-user/{user_id}", response_class=JSONResponse, name="ui_totp_rotate_user")
def ui_totp_rotate_user_route(
    request: Request,
    user_id: int,
    target_version: int = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    """Rotate a specific user's TOTP key to the target version."""
    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"success": False, "error": str(e)}
        )

    # Get user
    user = crud.user.get_user_by_id(db, user_id)
    if not user:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"success": False, "error": "User not found"}
        )

    # Perform rotation
    success = totp_key_manager.rotate_user_key(db, user, target_version=target_version)

    return JSONResponse(content={
        "success": success,
        "user_id": user_id,
        "username": user.username,
        "new_version": target_version if success else None
    })


@router.get("/generate-key", response_class=JSONResponse, name="ui_totp_generate_key")
def ui_totp_generate_key_route(
    request: Request,
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    """Generate a new Fernet encryption key for rotation."""
    new_key = totp_key_manager.generate_new_key()

    return JSONResponse(content={
        "success": True,
        "key": new_key,
        "instructions": (
            "Add this key to your .env file as TOTP_ENCRYPTION_KEY_V2=<key>, "
            "restart the server, then use the rotation interface to migrate users."
        )
    })
