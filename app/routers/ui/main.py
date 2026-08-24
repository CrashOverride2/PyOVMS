from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from pathlib import Path
import logging
from typing import Optional

try:
    import markdown
except ImportError:
    markdown = None
    logging.getLogger(__name__).warning("The 'markdown' library is not installed. Privacy policy will not render correctly.")

from app.models import db as models_db
from app.dependencies import get_user_from_request_cookie
from . import templates, get_common_template_vars 

from .dashboard import router as dashboard_ui_router
from .vehicles import router as vehicles_ui_router
from .users import router as users_ui_router
from .profile import router as profile_ui_router
from .auth import router as auth_ui_router
from .registration import router as registration_ui_router
from .admin import router as admin_ui_router
from .autoprovision import router as autoprovision_ui_router
from .totp_rotation import router as totp_rotation_ui_router
from .webauthn import router as webauthn_ui_router
from .security_events import router as security_events_ui_router
from .wellknown import router as wellknown_ui_router
from app.utils.csrf_dependency import csrf_protect

router = APIRouter(tags=["Web UI Main"], dependencies=[Depends(csrf_protect)])

@router.get("/", include_in_schema=False)
def root(
    request: Request,
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
):
    if not current_user:
        return RedirectResponse(url=request.url_for('ui_login_form'))
    if current_user.is_admin:
        return RedirectResponse(url=request.url_for('ui_admin_dashboard'))
    return RedirectResponse(url=request.url_for('ui_dashboard'))

@router.get("/privacy", response_class=HTMLResponse, name="ui_privacy_policy")
def ui_privacy_policy(
    request: Request,
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
):
    # The policy is operator-supplied and not shipped with the source. Without one there
    # is nothing to show, so 404 rather than render a page whose entire content is an
    # error message — the footer link is hidden in that case anyway.
    project_root = Path(__file__).resolve().parent.parent.parent.parent
    policy_file = project_root / "privacy_policy.md"
    if not policy_file.exists():
        raise HTTPException(status_code=404, detail="No privacy policy has been published on this instance.")

    common_vars = get_common_template_vars(request, current_user)
    policy_html = "<h1>Error</h1><p>Could not render privacy policy.</p>"
    try:
        if markdown is None:
             policy_html = "<h1>Configuration Error</h1><p>The 'markdown' library is not installed on the server.</p>"
        else:
            policy_html = markdown.markdown(policy_file.read_text(encoding="utf-8"))
    except Exception as e:
        policy_html = f"<h1>Error</h1><p>An error occurred: {e}</p>"

    return templates.TemplateResponse(request, "privacy_policy.html", {**common_vars, "page_title": "Privacy Policy", "policy_html": policy_html})

router.include_router(dashboard_ui_router)
router.include_router(auth_ui_router)
router.include_router(registration_ui_router)
router.include_router(admin_ui_router, prefix="/admin", tags=["Web UI - Admin"])
router.include_router(autoprovision_ui_router, prefix="/admin/autoprovision", tags=["Web UI - Auto Provisioning"])
router.include_router(totp_rotation_ui_router, prefix="/admin/totp", tags=["Web UI - TOTP Rotation"])
router.include_router(security_events_ui_router, prefix="/admin", tags=["Web UI - Security Events"])
router.include_router(vehicles_ui_router, prefix="/vehicle", tags=["Web UI - Vehicles"])
router.include_router(users_ui_router, prefix="/users", tags=["Web UI - Users"])
router.include_router(profile_ui_router, prefix="/profile", tags=["Web UI - Profile"])
router.include_router(webauthn_ui_router, prefix="/profile", tags=["Web UI - WebAuthn"])
router.include_router(wellknown_ui_router)