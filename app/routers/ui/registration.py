from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
import logging
from pydantic import ValidationError 
import datetime

from app.database import get_db
from app import crud, notifications
from app.models import api as models_api
from app.models import db as models_db
from app.config import settings
from . import templates, get_common_template_vars, get_translator
from app.dependencies import get_user_from_request_cookie, get_client_ip
from app.security_manager import security_manager
from app.services.disposable_email_service import (
    disposable_email_service,
    DisposableEmailBlocked,
    DisposableEmailListUnavailable,
)
from app.security_events import security_event_logger, SecurityEventType
from app.csrf_protection import verify_csrf_token
from app.utils.urls import external_url_for

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Web UI - Registration"])

@router.get("/register", response_class=HTMLResponse, name="ui_register_form")
def ui_register_form_route(request: Request, current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)):
    if not settings.ALLOW_USER_REGISTRATION:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Registration is disabled.")
    if current_user:
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)
    
    common_vars = get_common_template_vars(request, current_user)
    return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "form_data": {}})

@router.post("/register", response_class=HTMLResponse, name="ui_register_submit")
def ui_register_submit_route(
    request: Request,
    background_tasks: BackgroundTasks,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    if not settings.ALLOW_USER_REGISTRATION:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Registration is disabled.")

    # Bound before the CSRF check, not after: the redirect below translates the
    # exception detail, and get_common_template_vars() is only reached further down.
    _ = get_translator(request)

    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        security_manager.record_failure(client_ip, 'api_general')
        register_form_url = str(request.url_for('ui_register_form'))
        return RedirectResponse(url=f"{register_form_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, None)
    form_data = {"username": username, "email": email}
    
    if password != confirm_password:
        security_manager.record_failure(client_ip, 'login')
        return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "error_message": "Passwords do not match.", "form_data": form_data})

    _generic_success_response = templates.TemplateResponse(request, "register_success.html", {
        **common_vars,
        "email": email,
        "valid_hours": settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
    })

    # Username/email collision check — return the same generic success page to prevent enumeration.
    # Internal logging records the real reason without exposing it to the caller.
    if crud.user.get_user_by_username(db, username):
        security_manager.record_failure(client_ip, 'login')
        logger.info(f"Registration rejected: username '{username}' already taken (shown generic success to caller).")
        return _generic_success_response

    if not all([settings.EMAIL_HOST, settings.EMAIL_SENDER]):
        logger.error("User registration failed because email server is not configured in settings.")
        return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "error_message": "Cannot process registration: Email server is not configured.", "form_data": form_data})

    try:
        user_in = models_api.UserCreate(username=username, email=email, password=password, is_active=False)
    except ValidationError as e:
        security_manager.record_failure(client_ip, 'login')
        error_detail = "Invalid input. Please check the form."
        if e.errors():
            first_error = e.errors()[0]
            field = first_error['loc'][0] if first_error.get('loc') and len(first_error['loc']) > 0 else "Field"
            error_detail = f"{str(field).capitalize()}: {first_error['msg']}"
        return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "error_message": error_detail, "form_data": form_data})

    try:
        disposable_email_service.check_email(db, user_in.email)
    except DisposableEmailBlocked:
        security_manager.record_failure(client_ip, 'api_general')
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.DISPOSABLE_EMAIL_BLOCKED,
            username=username,
            ip_address=client_ip,
            details={"email": user_in.email, "domain": user_in.email.split("@")[-1].lower()},
        )
        return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "error_message": _("Disposable email addresses are not allowed."), "form_data": form_data})
    except DisposableEmailListUnavailable as exc:
        logger.warning("Disposable email validation unavailable during registration: %s", exc)
        return templates.TemplateResponse(request, "register.html", {**common_vars, "page_title": "Register", "error_message": "Unable to validate email domain right now. Please try again later.", "form_data": form_data})

    # Email collision — same generic response to avoid enumeration
    if crud.user.get_user_by_email(db, user_in.email):
        security_manager.record_failure(client_ip, 'login')
        logger.info(f"Registration rejected: email '{email}' already registered (shown generic success to caller).")
        return _generic_success_response

    new_user = crud.user.create_user(db, user_in)
    token = crud.user.set_user_verification_token(db, new_user)
    # Mailed link — host from configuration, never from the Host header. See
    # app/utils/urls.py.
    verification_link = external_url_for(request, 'ui_verify_email', token=token)

    background_tasks.add_task(notifications.send_verification_email, new_user, verification_link)
    if settings.SEND_ADMIN_REGISTRATION_EMAIL:
        background_tasks.add_task(notifications.send_new_user_admin_notification, new_user)

    return templates.TemplateResponse(request, "register_success.html", {
        **common_vars,
        "email": new_user.email,
        "valid_hours": settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
    })

@router.get("/verify/{token}", response_class=HTMLResponse, name="ui_verify_email")
def ui_verify_email_route(request: Request, token: str, db: Session = Depends(get_db)):
    _ = get_translator(request)
    common_vars = get_common_template_vars(request, None)
    user = crud.user.get_user_by_verification_token(db, token=token)

    if not user or not user.email_verification_token_expires_at:
        return templates.TemplateResponse(request, "verification_failed.html", {**common_vars})

    # Check if already verified (token already used)
    if user.is_active and not user.email_verification_token:
        return RedirectResponse(
            url=f"{request.url_for('ui_login_form')}?error_message={quote_plus(_("This verification link has already been used."))}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Only a naive value is UTC by convention. Overwriting the tzinfo of an aware one
    # (PostgreSQL returns those) moves the deadline by the session's UTC offset, which
    # east of UTC means the link expires early and west of it that it outlives its
    # window. Same handling as the password-reset expiry in ui/auth.py.
    expires_at_aware = user.email_verification_token_expires_at
    if expires_at_aware.tzinfo is None:
        expires_at_aware = expires_at_aware.replace(tzinfo=datetime.timezone.utc)
    if expires_at_aware < datetime.datetime.now(datetime.timezone.utc):
        return templates.TemplateResponse(request, "verification_failed.html", {**common_vars})

    # Single-use: Clear token immediately upon use
    crud.user.activate_user_and_clear_token(db, user)
    return RedirectResponse(url=f"{request.url_for('ui_login_form')}?success_message={quote_plus(_("Your account has been activated! You can now log in."))}", status_code=status.HTTP_303_SEE_OTHER)
