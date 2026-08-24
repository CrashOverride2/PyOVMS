from urllib.parse import quote_plus
import psutil
import datetime
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request, Depends, Form, status, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
try:
    import markdown
except ImportError:
    markdown = None
    logging.getLogger(__name__).warning("The 'markdown' library is not installed. Info box will not render markdown.")

from app.utils.safe_markdown import render_safe_markdown
from app.database import get_db
from app.connection_manager import manager
from app import crud
from app.models import db as models_db
from . import templates, get_common_template_vars
from app.dependencies import require_admin_user_from_cookie
from app.services.mqtt_auth_manager import mqtt_manager as mqtt_auth_manager
from app.services.disposable_email_service import (
    disposable_email_service,
    DisposableEmailListUnavailable,
    DEFAULT_LOCAL_PATH,
    DEFAULT_REFRESH_HOURS,
    DEFAULT_REMOTE_URL,
)
from app.config import settings
from app.csrf_protection import verify_csrf_token

logger = logging.getLogger(__name__)
router = APIRouter()
SERVER_START_TIME = datetime.datetime.now(datetime.timezone.utc)


# Shared with the user dashboard so the two renderers cannot drift again.
_render_safe_markdown = render_safe_markdown

@router.get("/dashboard", response_class=HTMLResponse, name="ui_admin_dashboard")
def ui_admin_dashboard(
    request: Request, 
    db: Session = Depends(get_db), 
    current_user: models_db.User = Depends(require_admin_user_from_cookie)
):
    common_vars = get_common_template_vars(request, current_user)
    
    # --- System Stats ---
    uptime = datetime.datetime.now(datetime.timezone.utc) - SERVER_START_TIME
    system_stats = {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "memory_used_gb": round(psutil.virtual_memory().used / (1024**3), 2),
        "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
        "uptime": str(uptime).split('.')[0],
        "log_file_exists": settings.LOG_FILE and Path(settings.LOG_FILE).exists(),
    }
    
    # --- Live Counts ---
    all_db_vehicles = manager.get_all_vehicle_infos(db)
    v2_online_count = len(manager.car_connections)
    v3_online_count = sum(1 for v in all_db_vehicles if v.connection_type in ('V3', 'V2+V3'))
    
    live_counts = {
        "total_users": crud.user.get_user_count(db),
        "total_vehicles": crud.vehicle.get_vehicle_count(db),
        "v2_online": v2_online_count,
        "v3_online": v3_online_count,
        "total_online": sum(1 for v in all_db_vehicles if v.authenticated),
        "mqtt_auth_enabled": mqtt_auth_manager.is_enabled()
    }

    info_box_settings = crud.system_setting.get_info_box_settings(db)
    info_box_html = ""
    if info_box_settings["enabled"] and info_box_settings["content"] and markdown:
        info_box_html = _render_safe_markdown(info_box_settings["content"])

    disposable_email_state = disposable_email_service.get_state(db)

    # --- Lifecycle status sets ---
    # Vehicles eligible to receive an inactivity warning on next cycle
    lifecycle_warn_ids = {v.id for v in crud.vehicle.get_vehicles_needing_unused_warning(db)}
    # Vehicles already warned and queued for auto-deletion
    lifecycle_delete_ids = {v.id for v in crud.vehicle.get_vehicles_to_auto_delete(db)}

    return templates.TemplateResponse(request, "admin_dashboard.html", {
        **common_vars,
        "page_title": "Admin Dashboard",
        "system_stats": system_stats,
        "live_counts": live_counts,
        "all_vehicles": all_db_vehicles,
        "info_box_settings": info_box_settings,
        "info_box_html_preview": info_box_html,
        "disposable_email_state": disposable_email_state,
        "lifecycle_warn_ids": lifecycle_warn_ids,
        "lifecycle_delete_ids": lifecycle_delete_ids,
    })

@router.get("/logs", response_class=HTMLResponse, name="ui_admin_logs")
def ui_admin_logs_route(
    request: Request,
    current_user: models_db.User = Depends(require_admin_user_from_cookie)
):
    """
    Admin logs page using WebSocket for real-time streaming.
    Initial log lines are loaded via WebSocket connection.
    """
    common_vars = get_common_template_vars(request, current_user)

    return templates.TemplateResponse(request, "admin_logs.html", {
        **common_vars,
        "page_title": "Server Logs",
    })

@router.post("/infobox", response_class=RedirectResponse, name="ui_admin_update_infobox")
def ui_admin_update_infobox_route(
    request: Request,
    info_box_enabled: bool = Form(False),
    info_box_title: str = Form(""),
    info_box_content: str = Form(""),
    info_box_type: str = Form("info"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_admin_user_from_cookie)
):
    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(
            url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(str(e.detail))}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    crud.system_setting.update_info_box_settings(
        db=db,
        enabled=info_box_enabled,
        title=info_box_title,
        content=info_box_content,
        box_type=info_box_type
    )
    return RedirectResponse(
        url=f"{request.url_for('ui_admin_dashboard')}?success_message=Info Box updated successfully.",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/vehicles/{vehicle_db_id}/clear-auto-delete", response_class=RedirectResponse, name="ui_admin_clear_vehicle_auto_delete")
def ui_admin_clear_vehicle_auto_delete(
    vehicle_db_id: int,
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_admin_user_from_cookie)
):
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(
            url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(str(e.detail))}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle = crud.vehicle.clear_unused_reminder(db, vehicle_db_id)
    if not vehicle:
        return RedirectResponse(
            url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus('Vehicle not found.')}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    logger.info(f"Admin {current_user.username} cleared auto-delete marking for vehicle {vehicle.vehicle_id}")
    return RedirectResponse(
        url=f"{request.url_for('ui_admin_dashboard')}?success_message={quote_plus(f'Auto-delete cancelled for vehicle {vehicle.vehicle_id}.')}",
        status_code=status.HTTP_303_SEE_OTHER
    )


@router.post("/disposable-email-settings", response_class=RedirectResponse, name="ui_admin_update_disposable_email_settings")
def ui_admin_update_disposable_email_settings_route(
    request: Request,
    enable_disposable_email_filter: bool = Form(False),
    disposable_email_source: str = Form("remote"),
    disposable_email_remote_url: str = Form(DEFAULT_REMOTE_URL),
    disposable_email_local_path: str = Form(str(DEFAULT_LOCAL_PATH)),
    disposable_email_refresh_hours: int = Form(DEFAULT_REFRESH_HOURS),
    disposable_email_whitelist: str = Form(""),
    refresh_now: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_admin_user_from_cookie)
):
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(
            url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(str(e.detail))}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    whitelist_set = disposable_email_service.parse_whitelist_input(disposable_email_whitelist)
    refresh_hours = disposable_email_refresh_hours if isinstance(disposable_email_refresh_hours, int) else DEFAULT_REFRESH_HOURS
    refresh_hours = refresh_hours if refresh_hours >= 0 else DEFAULT_REFRESH_HOURS

    disposable_email_service.update_settings(
        db=db,
        enabled=enable_disposable_email_filter,
        source=disposable_email_source,
        remote_url=disposable_email_remote_url.strip() or DEFAULT_REMOTE_URL,
        local_path=disposable_email_local_path.strip() or str(DEFAULT_LOCAL_PATH),
        refresh_hours=refresh_hours,
        whitelist=whitelist_set,
    )

    refresh_requested = bool(refresh_now)
    if refresh_requested and enable_disposable_email_filter and disposable_email_source == "remote":
        try:
            count = disposable_email_service.refresh_remote_now(db)
            message = f"Settings saved. Remote list refreshed ({count} domains loaded)."
            return RedirectResponse(
                url=f"{request.url_for('ui_admin_dashboard')}?success_message={quote_plus(str(message))}",
                status_code=status.HTTP_303_SEE_OTHER
            )
        except DisposableEmailListUnavailable as exc:
            logger.warning("Failed to refresh disposable email list: %s", exc)
            return RedirectResponse(
                url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(f'Settings saved, but refresh failed: {exc}')}",
                status_code=status.HTTP_303_SEE_OTHER
            )

    return RedirectResponse(
        url=f"{request.url_for('ui_admin_dashboard')}?success_message=Disposable email settings saved.",
        status_code=status.HTTP_303_SEE_OTHER
    )
