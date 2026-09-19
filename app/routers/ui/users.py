from urllib.parse import quote_plus
import logging

from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
from pydantic import ValidationError 
from zoneinfo import available_timezones

from app.database import get_db
from app import crud
from app.models import api as models_api
from app.models import db as models_db
from . import templates, get_common_template_vars, get_translator, format_validation_error
from app.dependencies import require_admin_user_from_cookie, get_client_ip
from app.csrf_protection import verify_csrf_token
from app.services.disposable_email_service import (
    disposable_email_service,
    DisposableEmailBlocked,
    DisposableEmailListUnavailable,
)
from app.security_events import log_admin_role_change, security_event_logger, SecurityEventType
from app.services.vehicle_service import (
    KartoDeletionFailed,
    trigger_karto_deletion_for_user_vehicles,
)
from app.utils.i18n_markers import N_

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("", response_class=HTMLResponse, name="ui_manage_users")
def ui_manage_users_route(
    request: Request, db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    common_vars = get_common_template_vars(request, current_admin)
    users = crud.user.get_users(db, limit=1000)
    lifecycle_warn_ids = {u.id for u in crud.user.get_users_needing_deletion_warning(db)}
    lifecycle_delete_ids = {u.id for u in crud.user.get_users_to_auto_delete(db)}
    user_vehicle_counts = {u.id: len(u.vehicles) for u in users}
    return templates.TemplateResponse(request, "users_management.html", {
        **common_vars,
        "users": users,
        "lifecycle_warn_ids": lifecycle_warn_ids,
        "lifecycle_delete_ids": lifecycle_delete_ids,
        "user_vehicle_counts": user_vehicle_counts,
        "page_title": N_("User Management")
    })

@router.get("/add", response_class=HTMLResponse, name="ui_add_user_form")
def ui_add_user_form_route(
    request: Request,
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    common_vars = get_common_template_vars(request, current_admin)
    return templates.TemplateResponse(request, "edit_user.html", {
        **common_vars,
        "user_to_edit": None,
        "all_timezones": sorted(available_timezones()),
        "page_title": N_("Add New User"),
        "form_action_url": request.url_for('ui_add_user_submit')
    })

@router.post("/add", response_class=RedirectResponse, name="ui_add_user_submit")
def ui_add_user_submit_route(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    full_name: Optional[str] = Form(None),
    password: str = Form(...),
    timezone: str = Form(...),
    is_admin: bool = Form(False),
    is_active: bool = Form(True),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie),
    client_ip: str = Depends(get_client_ip)
):
    redirect_url_on_error = str(request.url_for('ui_add_user_form'))
    common_vars = get_common_template_vars(request, current_admin)
    _ = common_vars["_"]

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    if timezone not in available_timezones():
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Invalid timezone selected."))}", status_code=status.HTTP_303_SEE_OTHER)
    # quote_plus over the whole message, not just the interpolated value: these two
    # run *before* UserCreate validates the form, so `username` and `email` are still
    # raw request input here and would otherwise land unescaped in the query string.
    if crud.user.get_user_by_username(db, username):
        msg = quote_plus(_("Username '%(name)s' already exists.") % {"name": username})
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)
    if email and crud.user.get_user_by_email(db, email):
        msg = quote_plus(_("Email '%(email)s' already registered.") % {"email": email})
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)

    try:
        user_in = models_api.UserCreate(
            username=username, email=email, full_name=full_name, password=password,
            is_admin=is_admin, is_active=is_active, timezone=timezone
        )
    except ValidationError as e:
        error_detail = format_validation_error(_, e)
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(str(error_detail))}", status_code=status.HTTP_303_SEE_OTHER)

    try:
        disposable_email_service.check_email(db, user_in.email)
    except DisposableEmailBlocked:
        ip_addr = request.client.host if request.client else None
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.DISPOSABLE_EMAIL_BLOCKED,
            username=username,
            ip_address=ip_addr,
            details={"email": user_in.email, "domain": user_in.email.split("@")[-1].lower()},
        )
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_('Disposable email addresses are not allowed.'))}", status_code=status.HTTP_303_SEE_OTHER)
    except DisposableEmailListUnavailable as exc:
        logger.warning("Disposable email validation unavailable when admin adds user: %s", exc)
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Unable to validate email domain right now. Please try again later."))}", status_code=status.HTTP_303_SEE_OTHER)

    new_user = crud.user.create_user(db, user_in)
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.USER_CREATED,
            user_id=new_user.id, username=username,
            ip_address=client_ip,
            details={"created_by": current_admin.username, "is_admin": is_admin}
        )
    except Exception:
        pass
    # Outside the block above on purpose: a failure to write USER_CREATED must not also
    # swallow the record of the privilege grant. log_admin_role_change() never raises.
    if new_user.is_admin:
        log_admin_role_change(
            db, target_id=new_user.id, target_username=new_user.username, granted=True,
            actor=current_admin, ip_address=client_ip, via="ui_create",
        )
    return RedirectResponse(url=f"{request.url_for('ui_manage_users')}?success_message={quote_plus(_("User '%(name)s' created successfully.") % {'name': username})}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/{user_id}/edit", response_class=HTMLResponse, name="ui_edit_user_form")
def ui_edit_user_form_route(
    request: Request, user_id: int, db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    common_vars = get_common_template_vars(request, current_admin)
    user_to_edit = crud.user.get_user_by_id(db, user_id)
    if not user_to_edit:
        return RedirectResponse(url=f"{request.url_for('ui_manage_users')}?error_message={quote_plus(_("User not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    
    return templates.TemplateResponse(request, "edit_user.html", {
        **common_vars,
        "user_to_edit": user_to_edit,
        "all_timezones": sorted(available_timezones()),
        "page_title": _("Edit User: %(name)s") % {"name": user_to_edit.username},
        "form_action_url": request.url_for('ui_edit_user_submit', user_id=user_id)
    })

@router.post("/{user_id}/edit", response_class=RedirectResponse, name="ui_edit_user_submit")
def ui_edit_user_submit_route(
    request: Request, user_id: int,
    username: str = Form(...),
    email: str = Form(...),
    full_name: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    timezone: str = Form(...),
    is_admin: bool = Form(False),
    is_active: bool = Form(True),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie),
    client_ip: str = Depends(get_client_ip)
):
    user_db = crud.user.get_user_by_id(db, user_id)
    redirect_url_on_error = str(request.url_for('ui_edit_user_form', user_id=user_id))
    common_vars = get_common_template_vars(request, current_admin)
    _ = common_vars["_"]

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    if not user_db:
        return RedirectResponse(url=f"{request.url_for('ui_manage_users')}?error_message={quote_plus(_("User not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    if timezone not in available_timezones():
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Invalid timezone selected."))}", status_code=status.HTTP_303_SEE_OTHER)

    # Raw form input at this point — UserUpdate has not validated it yet. Same reason
    # the add-user route above escapes the whole message.
    if username != user_db.username and crud.user.get_user_by_username(db, username):
        msg = quote_plus(_("Username '%(name)s' already exists.") % {"name": username})
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)
    if email and email != user_db.email and crud.user.get_user_by_email(db, email):
        msg = quote_plus(_("Email '%(email)s' already registered.") % {"email": email})
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)

    # The invariant first — see the same check in routers/api/users.py for why it goes
    # ahead of the self-checks rather than behind them.
    if (not is_admin or not is_active) and crud.user.is_last_active_admin(db, user_db):
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Cannot remove the last remaining admin account."))}", status_code=status.HTTP_303_SEE_OTHER)

    if user_db.id == current_admin.id:
        if not is_active: return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Admin cannot deactivate themselves."))}", status_code=status.HTTP_303_SEE_OTHER)
        if not is_admin: return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Admin cannot remove their own admin status."))}", status_code=status.HTTP_303_SEE_OTHER)

    update_payload = {"username": username, "email": email, "full_name": full_name, "is_admin": is_admin, "is_active": is_active, "timezone": timezone}
    if password: update_payload["password"] = password

    try:
        user_in = models_api.UserUpdate(**update_payload)
    except ValidationError as e:
        error_detail = format_validation_error(_, e)
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(str(error_detail))}", status_code=status.HTTP_303_SEE_OTHER)

    if user_in.email and user_in.email != user_db.email:
        try:
            disposable_email_service.check_email(db, user_in.email)
        except DisposableEmailBlocked:
            ip_addr = request.client.host if request.client else None
            security_event_logger.log_event(
                db=db,
                event_type=SecurityEventType.DISPOSABLE_EMAIL_BLOCKED,
                username=username,
                ip_address=ip_addr,
                details={"email": user_in.email, "domain": user_in.email.split("@")[-1].lower()},
            )
            return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_('Disposable email addresses are not allowed.'))}", status_code=status.HTTP_303_SEE_OTHER)
        except DisposableEmailListUnavailable as exc:
            logger.warning("Disposable email validation unavailable when admin edits user: %s", exc)
            return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_("Unable to validate email domain right now. Please try again later."))}", status_code=status.HTTP_303_SEE_OTHER)

    old_is_active = user_db.is_active
    old_is_admin = user_db.is_admin
    crud.user.update_user(db, user_db, user_in)
    if is_admin != old_is_admin:
        log_admin_role_change(
            db, target_id=user_id, target_username=user_db.username, granted=is_admin,
            actor=current_admin, ip_address=client_ip, via="ui_update",
        )
    if is_active != old_is_active:
        try:
            event_type = SecurityEventType.USER_ENABLED if is_active else SecurityEventType.USER_DISABLED
            security_event_logger.log_event(
                db=db, event_type=event_type,
                user_id=user_id, username=username,
                ip_address=client_ip,
                details={"changed_by": current_admin.username}
            )
        except Exception:
            pass
    return RedirectResponse(url=f"{request.url_for('ui_manage_users')}?success_message={quote_plus(_("User '%(name)s' updated successfully.") % {'name': username})}", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/{user_id}/delete", response_class=RedirectResponse, name="ui_delete_user")
async def ui_delete_user_route(
    request: Request, user_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    redirect_url = str(request.url_for('ui_manage_users'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    user_to_delete = crud.user.get_user_by_id(db, user_id)

    if not user_to_delete:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("User not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    if crud.user.is_last_active_admin(db, user_to_delete):
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("Cannot delete the last remaining admin account."))}", status_code=status.HTTP_303_SEE_OTHER)

    if user_to_delete.id == current_admin.id:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("Admin cannot delete themselves."))}", status_code=status.HTTP_303_SEE_OTHER)

    # Karto first, and only proceed if it confirmed. The vehicles of this account are
    # removed by the ORM cascade, which passes none of the vehicle-deletion routes, so
    # their trip history would otherwise be left behind — and a vehicle id is free for
    # re-registration the moment the row is gone.
    try:
        await trigger_karto_deletion_for_user_vehicles(db, user_to_delete, current_admin)
    except KartoDeletionFailed as e:
        logger.error(f"Aborting deletion of user '{user_to_delete.username}': {e}")
        return RedirectResponse(
            url=f"{redirect_url}?error_message="
                f"{quote_plus(_('Trip data could not be deleted right now, so the account was kept. Please retry.'))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    deleted_username = user_to_delete.username
    deleted_user_id = user_to_delete.id
    if not crud.user.delete_user(db, user_id):
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("Could not delete user %(name)s. They may own vehicles or AP profiles.") % {'name': deleted_username})}", status_code=status.HTTP_303_SEE_OTHER)

    try:
        # user_id=None: the row is already gone, and security_events.user_id is a real
        # foreign key — writing the dead id here failed the insert, and the `except`
        # below swallowed it, so the deletion was the one action missing from the audit
        # trail. The id is kept in the details instead.
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.USER_DELETED,
            user_id=None, username=deleted_username,
            ip_address=client_ip,
            details={"deleted_by": current_admin.username, "deleted_user_id": deleted_user_id}
        )
    except Exception:
        pass
    return RedirectResponse(url=f"{redirect_url}?success_message={quote_plus(_("User '%(name)s' deleted successfully.") % {'name': deleted_username})}", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/{user_id}/clear-auto-delete", response_class=RedirectResponse, name="ui_clear_user_auto_delete")
def ui_clear_user_auto_delete_route(
    request: Request, user_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    redirect_url = str(request.url_for('ui_manage_users'))

    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    user = crud.user.clear_account_deletion_reminder(db, user_id)
    if not user:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("User not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    logger.info(f"Admin {current_admin.username} cleared auto-delete marking for user {user.username}")
    return RedirectResponse(url=f"{redirect_url}?success_message={quote_plus(_("Auto-delete cancelled for user %(name)s.") % {'name': user.username})}", status_code=status.HTTP_303_SEE_OTHER)
