from fastapi import APIRouter, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from urllib.parse import quote_plus
import logging

try:
    import markdown
except ImportError:
    markdown = None
    logging.getLogger(__name__).warning("The 'markdown' library is not installed. Info box will not render markdown.")

from app.utils.safe_markdown import render_safe_markdown
from app.database import get_db
from app.connection_manager import manager
from app.models import db as models_db
from . import templates, get_common_template_vars, get_translator
from app.dependencies import require_current_user_from_cookie_fully_authenticated
from app import crud

router = APIRouter(tags=["Web UI - Dashboard"])


# Shared with the admin dashboard so the two renderers cannot drift again.
_render_safe_markdown = render_safe_markdown

@router.get("/dashboard", response_class=HTMLResponse, name="ui_dashboard")
def ui_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated) 
):
    _ = get_translator(request)
    if current_user.is_admin:
        return RedirectResponse(url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(_("Admins do not have a vehicle dashboard."))}", status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    vehicle_infos = manager.get_all_vehicle_infos(db, current_user)
    
    info_box_settings = crud.system_setting.get_info_box_settings(db)
    info_box_html = ""
    if info_box_settings["enabled"] and info_box_settings["content"] and markdown:
        info_box_html = _render_safe_markdown(info_box_settings["content"])

    return templates.TemplateResponse(request, "index.html", {
        **common_vars,
        "vehicles": vehicle_infos,
        "page_title": "PyOVMS Dashboard",
        "info_box_settings": info_box_settings,
        "info_box_html": info_box_html,
    })
