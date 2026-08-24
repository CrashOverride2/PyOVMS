"""
Security Events Dashboard UI routes.
"""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.dependencies import require_admin_user_from_cookie
from app.models.db import User
from app.routers.ui import get_common_template_vars, templates

router = APIRouter()


@router.get("/blocked-ips", response_class=HTMLResponse, name="ui_blocked_ips")
def ui_blocked_ips(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin_user_from_cookie),
):
    """Display the blocked IPs management page."""
    context = get_common_template_vars(request, current_admin)
    context.update({"page_title": "Blocked IPs"})
    return templates.TemplateResponse(request, "blocked_ips.html", context)


@router.get("/security-events", response_class=HTMLResponse, name="ui_security_events_dashboard")
def ui_security_events_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: User = Depends(require_admin_user_from_cookie)
):
    """Display security events dashboard."""
    context = get_common_template_vars(request, current_admin)
    context.update({
        "page_title": "Security Events Dashboard"
    })

    return templates.TemplateResponse(request, "security_events_dashboard.html", context)
