import re
from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session
from typing import Optional
import datetime
import logging
from pydantic import ValidationError
from zoneinfo import available_timezones


from app.database import get_db
from app import crud, security
from app.models import api as models_api
from app.models import db as models_db
from app.models.db import WebAuthnCredential
from . import templates, get_common_template_vars, get_translator, format_validation_error
from app.utils.i18n_markers import N_
from app.dependencies import require_current_user_from_cookie_fully_authenticated, get_client_ip
from app.config import settings
from app.csrf_protection import verify_csrf_token, get_csrf_token
from app.security_events import security_event_logger, SecurityEventType
from app.security_manager import security_manager
from app.services.vehicle_service import (
    KartoDeletionFailed,
    trigger_karto_deletion_for_user_vehicles,
)
from app.utils.timestamps import as_utc
from app.utils.step_up import (
    has_recent_reauth,
    mark_reauthenticated,
)
from fastapi.responses import JSONResponse


logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/csrf-token", name="ui_profile_get_csrf_token")
def get_profile_csrf_token(
    request: Request,
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """Get CSRF token for mobile app API key creation."""
    csrf_token = get_csrf_token(request)
    return JSONResponse(content={"csrf_token": csrf_token})

@router.get("", response_class=HTMLResponse, name="ui_profile_page") 
def ui_profile_page_route(
    request: Request,
    db: Session = Depends(get_db), 
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    common_vars = get_common_template_vars(request, current_user)
    api_keys = crud.apikey.get_api_keys_for_user(db, user_id=current_user.id)
    now_utc_for_template = datetime.datetime.now(datetime.timezone.utc)

    is_totp_enabled = current_user.is_totp_enabled
    newly_created_api_keys = request.session.pop("new_api_keys_to_display", [])

    # Get WebAuthn credentials for the user
    webauthn_credentials = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == current_user.id,
        WebAuthnCredential.is_active == True
    ).order_by(WebAuthnCredential.created_at.desc()).all()

    config_backups = crud.config_backup.list_backups(db, owner_id=current_user.id)

    return templates.TemplateResponse(request, "profile.html", {
        **common_vars,
        "page_title": N_("My Profile"),
        "api_keys": api_keys,
        "now_utc": now_utc_for_template,
        "is_totp_enabled": is_totp_enabled,
        "newly_created_api_keys": newly_created_api_keys,
        "all_timezones": sorted(available_timezones()),
        "webauthn_credentials": webauthn_credentials,
        # The tab is only rendered when this is non-empty — see profile.html. The
        # groups are what the tab actually iterates: one block per device.
        "config_backups": config_backups,
        "config_backup_groups": crud.config_backup.group_by_device(config_backups),
    })

def _reissue_session_cookie(request: Request, response, user) -> None:
    """
    Give the acting session a token carrying the new token_version.

    Changing the second factor bumps token_version, which is what ends any *other*
    session — including one an attacker holds. Without re-issuing here the user would
    be logged out by their own security action, which reads as a bug and teaches
    people not to touch 2FA settings.
    """
    from app import security as _security

    expires = datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = _security.create_access_token_with_2fa_status(
        username=user.username, is_2fa_completed=True, expires_delta=expires,
        token_version=user.token_version or 0,
    )
    is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"
    response.set_cookie(
        key="__Host-access_token" if is_secure else "access_token",
        value=f"Bearer {token}",
        httponly=True,
        max_age=int(expires.total_seconds()),
        samesite="lax",
        secure=is_secure,
        path="/",
    )


# Actions that change how the account can be signed into. Each of these creates or
# removes a way in, so a session alone must not be enough — see app.utils.step_up.
def _needs_step_up(request: Request, current_user, tab: str):
    """
    Returns a RedirectResponse to the confirmation page, or None if the caller may
    proceed.

    Redirecting rather than taking a password inline keeps every existing form
    untouched and covers the JS-driven flows too: the user confirms once and then
    repeats the action within the window.
    """
    if has_recent_reauth(request, current_user.id):
        return None
    target = f"{request.url_for('ui_profile_page')}?tab={tab}"
    return RedirectResponse(
        url=f"{request.url_for('ui_confirm_password_form')}?next_url={quote_plus(str(target))}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/confirm-password", response_class=HTMLResponse, name="ui_confirm_password_form")
def ui_confirm_password_form_route(
    request: Request,
    next_url: str = "",
    error_message: str = "",
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
):
    common_vars = get_common_template_vars(request, current_user)
    return templates.TemplateResponse(request, "confirm_password.html", {
        **common_vars,
        "page_title": N_("Confirm Password"),
        "csrf_token": get_csrf_token(request),
        "next_url": _safe_next_url(request, next_url),
        "error_message": error_message,
    })


def _safe_next_url(request: Request, candidate: str) -> str:
    """
    Only ever redirect back into this application.

    The target comes from a query parameter, so without this the confirmation page
    would be an open redirect — and one that a user reaches *after* proving their
    password, which is exactly when they are least suspicious of where they land.
    """
    default = str(request.url_for('ui_profile_page'))
    if not candidate:
        return default
    base = str(request.base_url).rstrip('/')
    if candidate.startswith(base + '/') or candidate == base:
        return candidate
    if candidate.startswith('/') and not candidate.startswith('//'):
        return candidate
    return default


@router.post("/confirm-password", response_class=RedirectResponse, name="ui_confirm_password_submit")
def ui_confirm_password_submit_route(
    request: Request,
    password: str = Form(...),
    next_url: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip),
):
    _ = get_translator(request)
    target = _safe_next_url(request, next_url)
    form_url = str(request.url_for('ui_confirm_password_form'))

    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(
            url=f"{form_url}?next_url={quote_plus(target)}&error_message={quote_plus(_(str(e.detail)))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if security_manager.is_blocked(client_ip):
        return RedirectResponse(
            url=f"{form_url}?next_url={quote_plus(target)}&error_message={quote_plus(_("Too many attempts. Try again later."))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if not security.verify_password(password, current_user.hashed_password):
        # Counted against the login budget: this is a password guess like any other,
        # and an attacker sitting on a stolen session is exactly who is guessing here.
        security_manager.record_failure(client_ip, 'login', username=current_user.username)
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.LOGIN_FAILED,
                user_id=current_user.id, username=current_user.username,
                ip_address=client_ip, details={"reason": "step_up_failed"},
            )
        except Exception:
            pass
        return RedirectResponse(
            url=f"{form_url}?next_url={quote_plus(target)}&error_message={quote_plus(_("Incorrect password."))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    mark_reauthenticated(request, current_user.id)
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/update", response_class=RedirectResponse, name="ui_update_profile_submit")
def ui_update_profile_submit_route(
    request: Request,
    full_name: str = Form(...),
    email: str = Form(...),
    timezone: str = Form(...),
    unit_preference: str = Form("metric"),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    base_redirect_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

    if timezone not in available_timezones():
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Invalid timezone selected."))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

    if unit_preference not in ("metric", "imperial"):
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Invalid unit preference."))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

    email_to_update = email.strip() or None
    full_name_to_update = full_name.strip() or None

    update_payload_dict = {}

    if email_to_update != current_user.email:
        # The e-mail address is where password reset links go, so changing it is a
        # way to take the account over outright. Gated; the rest of the profile
        # (name, timezone, units) is not.
        step_up = _needs_step_up(request, current_user, "info")
        if step_up:
            return step_up
        if email_to_update:
            update_payload_dict['email'] = email_to_update
            existing_user = crud.user.get_user_by_email(db, email=email_to_update)
            if existing_user and existing_user.id != current_user.id:
                # Escape the message only — `&tab=info` is a separate parameter and
                # must stay outside the escaped part. Without this an address
                # containing '&' would inject query parameters of its own.
                msg = quote_plus(_("The email '%(email)s' is already registered.") % {"email": email_to_update})
                return RedirectResponse(url=f"{base_redirect_url}?error_message={msg}&tab=info", status_code=status.HTTP_303_SEE_OTHER)
        else:
             update_payload_dict['email'] = None

    if full_name_to_update != current_user.full_name:
        update_payload_dict['full_name'] = full_name_to_update

    if timezone != current_user.timezone:
        update_payload_dict['timezone'] = timezone

    if unit_preference != getattr(current_user, 'unit_preference', 'metric'):
        update_payload_dict['unit_preference'] = unit_preference

    if not update_payload_dict:
        return RedirectResponse(url=f"{base_redirect_url}?info_message={quote_plus(_("No changes detected."))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

    try:
        user_in_update = models_api.UserUpdate(**update_payload_dict)
    except ValidationError as e:
        error_detail = format_validation_error(_, e)
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(str(error_detail))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

    crud.user.update_user(db=db, user_db=current_user, user_in=user_in_update)

    return RedirectResponse(url=f"{base_redirect_url}?success_message={quote_plus(_("Profile updated successfully."))}&tab=info", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/change-password", response_class=RedirectResponse, name="ui_change_password_submit")
def ui_change_password_submit_route(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_new_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    base_redirect_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)

    if new_password != confirm_new_password:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("New passwords do not match."))}&tab=password", status_code=status.HTTP_303_SEE_OTHER) 

    if not security.verify_password(current_password, current_user.hashed_password):
        security_manager.record_failure(client_ip, 'login')
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Incorrect current password."))}&tab=password", status_code=status.HTTP_303_SEE_OTHER) 

    try:
        user_in_update = models_api.UserUpdate(password=new_password)
    except ValidationError as e:
        security_manager.record_failure(client_ip, 'login')
        error_detail = format_validation_error(_, e)
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(str(error_detail))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)
        
    crud.user.update_user(db=db, user_db=current_user, user_in=user_in_update)
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.PASSWORD_CHANGED,
            user_id=current_user.id, username=current_user.username,
            ip_address=client_ip
        )
    except Exception:
        pass
    # The user just proved their old password; no reason to ask again immediately.
    mark_reauthenticated(request, current_user.id)
    redirect = RedirectResponse(url=f"{base_redirect_url}?success_message={quote_plus(_("Password updated successfully."))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)
    # update_user() bumped token_version, which ends every other session — the point
    # of changing a password after a suspected compromise. The 2FA routes re-issue
    # the acting session's cookie for that reason; this one did not, so the redirect
    # above was refused and the person who had just changed their password landed
    # on the login page instead of the success message.
    _reissue_session_cookie(request, redirect, current_user)
    return redirect

@router.post("/apikeys/create", response_class=RedirectResponse, name="ui_create_api_key")
def ui_create_api_key_route(
    request: Request,
    key_name: str = Form(..., min_length=1, max_length=100),
    expires_in_days: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    base_redirect_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

    step_up = _needs_step_up(request, current_user, "apikeys")
    if step_up:
        return step_up
    
    expires_delta = None
    if expires_in_days and expires_in_days.strip():
        try:
            days_int = int(expires_in_days)
            if days_int <= 0:
                return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Expiry days must be a positive number."))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)
            expires_delta = datetime.timedelta(days=days_int)
        except (ValueError, TypeError):
            return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Invalid value for expiry days."))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

    try:
        db_key, plain_key = crud.apikey.create_api_key(db, user_id=current_user.id, name=key_name, expires_delta=expires_delta)
    except ValueError as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(str(str(e)))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.API_KEY_CREATED,
            user_id=current_user.id, username=current_user.username,
            ip_address=client_ip, details={"key_name": key_name}
        )
    except Exception:
        pass

    new_keys_list = request.session.get("new_api_keys_to_display", [])
    new_keys_list.append({"name": key_name, "key": plain_key, "prefix": db_key.key_prefix})
    request.session["new_api_keys_to_display"] = new_keys_list

    final_url = f"{base_redirect_url}?success_message={quote_plus(_("API Key '%(name)s' created.") % {'name': key_name})}&tab=apikeys#new-key-{db_key.key_prefix}"
    return RedirectResponse(url=final_url, status_code=status.HTTP_303_SEE_OTHER)

@router.post("/apikeys/{api_key_id}/delete", response_class=RedirectResponse, name="ui_delete_api_key")
def ui_delete_api_key_route(
    request: Request,
    api_key_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    base_redirect_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

    api_key_to_delete = crud.apikey.get_api_key_by_id_and_user(db, api_key_id=api_key_id, user_id=current_user.id)

    if not api_key_to_delete:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("API Key not found or not owned by you."))}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

    crud.apikey.delete_api_key_by_id_and_user(db, api_key_id=api_key_id, user_id=current_user.id)
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.API_KEY_REVOKED,
            user_id=current_user.id, username=current_user.username,
            ip_address=client_ip, details={"key_name": api_key_to_delete.name}
        )
    except Exception:
        pass
    return RedirectResponse(url=f"{base_redirect_url}?success_message={quote_plus(_("API Key '%(name)s' deleted.") % {'name': api_key_to_delete.name})}&tab=apikeys", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/2fa/totp/setup", response_class=HTMLResponse, name="ui_totp_setup_form")
def ui_totp_setup_form_route(
    request: Request,
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    common_vars = get_common_template_vars(request, current_user)
    if current_user.is_totp_enabled:
        return RedirectResponse(url=f"{request.url_for('ui_profile_page')}?error_message={quote_plus(_("TOTP is already enabled."))}&tab=2fa", status_code=status.HTTP_303_SEE_OTHER)

    # Gated here as well as at /enable so the password is asked for before a secret is
    # generated and shown, rather than after the user has scanned the QR code.
    step_up = _needs_step_up(request, current_user, "2fa")
    if step_up:
        return step_up

    pending_secret = security.generate_totp_secret()
    request.session["pending_totp_secret"] = pending_secret 

    otpauth_uri = security.get_totp_uri(pending_secret, current_user.username, settings.OTP_ISSUER_NAME)
    qr_code_data_uri = security.generate_qr_code_data_uri(otpauth_uri)
    
    return templates.TemplateResponse(request, "profile_totp_setup.html", {
        **common_vars,
        "page_title": N_("Setup Authenticator App (TOTP)"),
        "otpauth_uri": otpauth_uri, 
        "qr_code_data_uri": qr_code_data_uri,
        "manual_setup_key": pending_secret 
    })

@router.post("/2fa/totp/enable", response_class=RedirectResponse, name="ui_totp_enable_submit")
def ui_totp_enable_submit_route(
    request: Request,
    totp_code: str = Form(..., min_length=6, max_length=6),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    profile_base_url = str(request.url_for('ui_profile_page'))
    setup_form_base_url = str(request.url_for('ui_totp_setup_form'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{setup_form_base_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    step_up = _needs_step_up(request, current_user, "2fa")
    if step_up:
        return step_up

    pending_secret = request.session.get("pending_totp_secret")
    if not pending_secret:
        return RedirectResponse(url=f"{profile_base_url}?tab=2fa&error_message={quote_plus(_("TOTP setup session expired. Please try again."))}", status_code=status.HTTP_303_SEE_OTHER)

    if security.verify_totp_code(pending_secret, totp_code):
        crud.user.enable_totp_for_user(db, current_user, pending_secret)
        if "pending_totp_secret" in request.session: del request.session["pending_totp_secret"]
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.TOTP_ENABLED,
                user_id=current_user.id, username=current_user.username,
                ip_address=client_ip
            )
        except Exception:
            pass
        redirect = RedirectResponse(url=f"{profile_base_url}?tab=2fa&success_message={quote_plus(_("Authenticator app enabled successfully."))}", status_code=status.HTTP_303_SEE_OTHER)
        _reissue_session_cookie(request, redirect, current_user)
        return redirect
    else:
        # Deliberately no username= here, unlike the login TOTP path. This is
        # enrollment: the user is already fully authenticated and is checking a code
        # against a secret in their own session, so it is not a guessing surface.
        # Feeding it into the per-account limit would let someone lock themselves out
        # of login by fumbling their authenticator during setup.
        security_manager.record_failure(client_ip, 'totp')
        return RedirectResponse(url=f"{setup_form_base_url}?error_message={quote_plus(_("Invalid TOTP code. Please try again."))}", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/2fa/totp/disable", response_class=RedirectResponse, name="ui_totp_disable_submit")
def ui_totp_disable_submit_route(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    profile_base_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{profile_base_url}?error_message={quote_plus(_(str(e.detail)))}&tab=2fa", status_code=status.HTTP_303_SEE_OTHER)

    step_up = _needs_step_up(request, current_user, "2fa")
    if step_up:
        return step_up

    if not current_user.is_totp_enabled:
        return RedirectResponse(url=f"{profile_base_url}?tab=2fa&error_message={quote_plus(_("TOTP is not enabled."))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.user.disable_totp_for_user(db, current_user)
    if "pending_totp_secret" in request.session: del request.session["pending_totp_secret"]
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.TOTP_DISABLED,
            user_id=current_user.id, username=current_user.username,
            ip_address=client_ip
        )
    except Exception:
        pass
    redirect = RedirectResponse(url=f"{profile_base_url}?tab=2fa&success_message={quote_plus(_("Authenticator app disabled successfully."))}", status_code=status.HTTP_303_SEE_OTHER)
    _reissue_session_cookie(request, redirect, current_user)
    return redirect

@router.post("/delete", response_class=RedirectResponse, name="ui_delete_profile_submit")
async def ui_delete_profile_submit_route(
    request: Request,
    delete_confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    _ = get_translator(request)
    profile_redirect_url = str(request.url_for('ui_profile_page'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{profile_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)
    
    step_up = _needs_step_up(request, current_user, "password")
    if step_up:
        return step_up

    if delete_confirmation != "DELETE":
        return RedirectResponse(url=f"{profile_redirect_url}?error_message={quote_plus(_("Incorrect confirmation text."))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)

    if current_user.is_admin and len(crud.user.get_active_admins(db)) <= 1:
        return RedirectResponse(url=f"{profile_redirect_url}?error_message={quote_plus(_("Cannot delete the only admin account."))}&tab=password", status_code=status.HTTP_303_SEE_OTHER)

    # Trip data first, and only proceed if Karto confirmed — the same rule the vehicle
    # routes follow. The account's vehicles disappear through the ORM cascade below,
    # which reaches no Karto code at all, so without this the GPS history of someone who
    # asked for their account to be deleted stayed on disk.
    try:
        await trigger_karto_deletion_for_user_vehicles(db, current_user, current_user)
    except KartoDeletionFailed as e:
        logger.error(f"Aborting deletion of account '{current_user.username}': {e}")
        return RedirectResponse(
            url=f"{profile_redirect_url}?error_message="
                f"{quote_plus(_('Your trip data could not be deleted right now, so the account was kept. Please try again.'))}"
                f"&tab=password",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    user_id_to_delete, username_deleted = current_user.id, current_user.username
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.USER_DELETED,
            user_id=user_id_to_delete, username=username_deleted,
            ip_address=client_ip, details={"self_delete": True}
        )
    except Exception:
        pass
    crud.user.delete_user(db, user_id=user_id_to_delete)
    
    login_url = str(request.url_for('ui_login_form'))
    redirect_response = RedirectResponse(url=f"{login_url}?success_message={quote_plus(_("Account '%(name)s' has been deleted.") % {'name': username_deleted})}", status_code=status.HTTP_303_SEE_OTHER)
    # Both variants — see the logout handler in ui/auth.py. The account is gone either
    # way, but leaving a cookie behind means the browser keeps presenting a token that
    # now resolves to nothing on every request.
    redirect_response.delete_cookie("access_token", path="/")
    redirect_response.delete_cookie("__Host-access_token", path="/", secure=True, httponly=True, samesite="Lax")
    
    session_keys = [f"2fa_passed_for_user_{user_id_to_delete}", "pending_2fa_user_id"]
    for key in session_keys:
        if key in request.session: del request.session[key]
        
    return redirect_response


# --- Configuration backups (OVMS Connect app snapshots) --------------------------
#
# Read, download and delete only. The app is the sole producer of a well-formed
# document, so there is no upload here, and "keep" (pinning an auto snapshot) is
# an app action too.
#
# Deliberately not behind CONFIG_BACKUP_ENABLED: the switch stops the app from
# taking snapshots and being handed them, but what is stored stays the user's to
# download and delete — an operator turning the feature off must not strand it.

@router.get("/config-backups/{backup_id}/download", name="ui_download_config_backup")
def ui_download_config_backup_route(
    request: Request,
    backup_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
):
    """The stored document, unchanged, as a .json download.

    No rehydration and no second container format: the server hands out what it
    holds, and the app imports a bare .json exactly as it imports its own ZIP.
    """
    backup = crud.config_backup.get_backup(db, owner_id=current_user.id, backup_id=backup_id)
    if backup is None:
        raise HTTPException(status_code=404, detail=N_("Backup not found."))

    stamp = as_utc(backup.created_at).strftime("%Y%m%d-%H%M%S")
    raw_name = f"ovms-connect-backup-{stamp}" + (f"-{backup.label}" if backup.label else "")
    # The label is user text. Anything outside this set — a quote, a CR/LF — would
    # otherwise be written straight into the header (see vehicles.py for the idiom).
    safe_name = re.sub(r'[^A-Za-z0-9_.-]+', '_', raw_name)[:120] + ".json"
    return Response(
        content=backup.payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
    )


@router.post("/config-backups/{backup_id}/delete", response_class=RedirectResponse,
             name="ui_delete_config_backup")
def ui_delete_config_backup_route(
    request: Request,
    backup_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
):
    _ = get_translator(request)
    base_redirect_url = str(request.url_for('ui_profile_page'))

    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_(str(e.detail)))}&tab=backups", status_code=status.HTTP_303_SEE_OTHER)

    if not crud.config_backup.delete_backup(db, owner_id=current_user.id, backup_id=backup_id):
        return RedirectResponse(url=f"{base_redirect_url}?error_message={quote_plus(_("Backup not found."))}&tab=backups", status_code=status.HTTP_303_SEE_OTHER)

    # After the last row is gone the tab disappears; setTab() falls back to "info".
    return RedirectResponse(url=f"{base_redirect_url}?success_message={quote_plus(_("Backup deleted."))}&tab=backups", status_code=status.HTTP_303_SEE_OTHER)
