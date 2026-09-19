from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from typing import Optional
import datetime

from app.database import get_db
from app import crud, security
from app.models import db as models_db, api as models_api
from app.config import settings
from . import templates, get_common_template_vars, get_translator
from app.dependencies import get_user_from_request_cookie, get_client_ip
from app.security_manager import security_manager
from app.websocket_manager import manager as websocket_manager
from app.csrf_protection import (
    get_csrf_token,
    verify_csrf_token,
    rotate_csrf_token,
    csrf_token_needs_renewal,
    CSRF_TOKEN_RENEW_AFTER,
)
from app.utils.step_up import mark_reauthenticated
from app.utils.urls import external_url_for
from app.utils.i18n_markers import N_
from app.utils.two_factor import (
    SecondFactor,
    password_login_is_disabled,
    required_second_factor,
    totp_is_accepted_for,
)
from app.security_events import security_event_logger, SecurityEventType
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Web UI - Authentication"])

@router.get("/login", response_class=HTMLResponse, name="ui_login_form")
def ui_login_form_route(request: Request, current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)):
    if current_user:
        if current_user.is_admin:
            return RedirectResponse(url=request.url_for('ui_admin_dashboard'), status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse(request, "login.html", {**common_vars, "page_title": N_("Login"), "csrf_token": csrf_token})

@router.post("/login", response_class=RedirectResponse, name="ui_login_submit")
def ui_login_submit_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    # Verify CSRF token
    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.CSRF_VIOLATION,
                ip_address=client_ip, details={"endpoint": "login", "reason": e.detail}
            )
        except Exception as _e:
            logger.warning(f"Security event logging failed (CSRF_VIOLATION): {_e}")
        login_form_url = str(request.url_for('ui_login_form'))
        return RedirectResponse(url=f"{login_form_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    login_form_url = str(request.url_for('ui_login_form'))

    # Generic error message to prevent username enumeration
    generic_error = _("Invalid credentials. Please check your username and password.")

    # Check per-username rate limit before any DB lookup (distributed brute-force detection)
    if security_manager.is_username_blocked(username):
        logger.warning(f"Login blocked for username '{username}' due to distributed rate limit (IP: {client_ip})")
        return RedirectResponse(url=f"{login_form_url}?error_message={quote_plus(generic_error)}", status_code=status.HTTP_303_SEE_OTHER)

    user = crud.user.get_user_by_username(db, username=username)

    # verify_password_for_user() runs bcrypt even when the user does not exist, so an
    # unknown username costs the same ~250 ms as a wrong password. Without that, the
    # response time answered the question the generic error message refuses to answer.
    if not security.verify_password_for_user(user, password):
        logger.warning(f"Failed login attempt from IP {client_ip} (username enumeration prevented)")
        security_manager.record_failure(client_ip, 'login', username=username)
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.LOGIN_FAILED,
                ip_address=client_ip, username=username,
                details={"reason": "invalid_credentials"}
            )
        except Exception as e:
            logger.warning(f"Security event logging failed (LOGIN_FAILED): {e}")
        return RedirectResponse(url=f"{login_form_url}?error_message={quote_plus(str(generic_error))}", status_code=status.HTTP_303_SEE_OTHER)

    if not user.is_active:
        # Still use generic error to prevent account enumeration
        logger.warning(f"Failed login attempt for inactive account from IP {client_ip}")
        security_manager.record_failure(client_ip, 'login', username=username)
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.LOGIN_FAILED,
                ip_address=client_ip, username=username,
                details={"reason": "account_inactive"}
            )
        except Exception as e:
            logger.warning(f"Security event logging failed (LOGIN_FAILED inactive): {e}")
        return RedirectResponse(url=f"{login_form_url}?error_message={quote_plus(str(generic_error))}", status_code=status.HTTP_303_SEE_OTHER)

    # Single source of truth for which factor this account needs — the TOTP submit
    # handler and the device-token API consult the same helper, so the three cannot
    # drift apart and quietly reopen a downgrade path.
    required_factor = required_second_factor(db, user)

    # If passwordless WebAuthn is enabled but no 2FA is set, password login should be disabled
    if password_login_is_disabled(db, user):
        error_message = _("Password login is disabled. Please use passwordless login with your security key.")
        logger.warning(f"Password login attempt blocked for user {username} - passwordless-only account")
        return RedirectResponse(url=f"{login_form_url}?error_message={quote_plus(str(error_message))}", status_code=status.HTTP_303_SEE_OTHER)

    if required_factor != SecondFactor.NONE:
        # NOT a session rotation, despite what this used to claim.
        #
        # SessionMiddleware stores the session *in* a signed cookie — there is no
        # server-side session id to rotate. clear() followed by update() with the same
        # data re-emits an identical cookie, so this sequence has never done anything.
        # It is kept only because it drops any key added between the two lines.
        #
        # What actually protects this login is that the authenticated identity lives in
        # the JWT cookie, which is minted fresh below and carries token_version. A
        # pre-set session cookie therefore cannot become an authenticated one.
        old_session_data = dict(request.session)
        request.session.clear()
        request.session.update(old_session_data)
        request.session["pending_2fa_user_id"] = user.id

        # Priority: WebAuthn 2FA > TOTP. When both are registered the security key is
        # not merely preferred, it is the only one accepted (see app.utils.two_factor).
        if required_factor == SecondFactor.WEBAUTHN:
            logger.info(f"User {user.username} has WebAuthn 2FA enabled. Redirecting to WebAuthn 2FA.")
            return RedirectResponse(url=request.url_for('ui_webauthn_2fa_form'), status_code=status.HTTP_303_SEE_OTHER)
        else:
            logger.info(f"User {user.username} has TOTP enabled. Redirecting to TOTP entry.")
            return RedirectResponse(url=request.url_for('ui_login_totp_form'), status_code=status.HTTP_303_SEE_OTHER)

    old_session_data = dict(request.session)
    request.session.clear()
    request.session.update(old_session_data)

    access_token_expires = datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token_with_2fa_status(
        username=user.username, is_2fa_completed=True, expires_delta=access_token_expires,
        token_version=user.token_version or 0,
    )

    crud.user.record_login(db, user)
    # A fresh login is by definition a recently proven password.
    mark_reauthenticated(request, user.id)
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.LOGIN_SUCCESS,
            user_id=user.id, username=user.username,
            ip_address=client_ip, details={"method": "password"}
        )
    except Exception as e:
        logger.warning(f"Security event logging failed (LOGIN_SUCCESS): {e}")

    redirect_url = request.url_for('ui_admin_dashboard') if user.is_admin else request.url_for('ui_dashboard')
    redirect_response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    # Secure cookie with __Host- prefix for additional security
    is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"
    redirect_response.set_cookie(
        key="__Host-access_token" if is_secure else "access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=int(access_token_expires.total_seconds()),
        samesite="Lax",
        secure=is_secure,
        path="/"
    )

    request.session[f"2fa_passed_for_user_{user.id}"] = True
    return redirect_response

@router.get("/login/totp", response_class=HTMLResponse, name="ui_login_totp_form")
def ui_login_totp_form_route(
    request: Request, 
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie),
    db: Session = Depends(get_db) 
):
    pending_user_id = request.session.get("pending_2fa_user_id")
    if not pending_user_id and not current_user:
        return RedirectResponse(url=request.url_for('ui_login_form'), status_code=status.HTTP_303_SEE_OTHER)
    
    if current_user and request.session.get(f"2fa_passed_for_user_{current_user.id}"):
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    username_for_display = crud.user.get_user_by_id(db, pending_user_id).username if pending_user_id else (current_user.username if current_user else "")

    return templates.TemplateResponse(request, "login_totp.html", {
        **common_vars, 
        "page_title": N_("Enter 2FA Code"),
        "username_for_totp": username_for_display
    })

@router.post("/login/totp", response_class=RedirectResponse, name="ui_login_totp_submit")
def ui_login_totp_submit_route(
    request: Request,
    totp_code: str = Form(..., min_length=6, max_length=6),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):

    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token, rotate_token=False)
    except HTTPException as e:
        return RedirectResponse(
            url=f"{request.url_for('ui_login_totp_form')}?error_message={quote_plus(_(str(e.detail)))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    pending_user_id = request.session.get("pending_2fa_user_id")
    if not pending_user_id:
        return RedirectResponse(url=f"{request.url_for('ui_login_form')}?error_message={quote_plus(_("Session expired. Please login again."))}", status_code=status.HTTP_303_SEE_OTHER)

    user = crud.user.get_user_by_id(db, user_id=pending_user_id)
    if not user or not user.is_active or not user.is_totp_enabled:
        if "pending_2fa_user_id" in request.session: del request.session["pending_2fa_user_id"]
        return RedirectResponse(url=f"{request.url_for('ui_login_form')}?error_message={quote_plus(_("Error with 2FA setup. Please login again."))}", status_code=status.HTTP_303_SEE_OTHER)

    # The stronger factor wins and switches the weaker one off. The login handler only
    # *redirects* accounts with a security key to the WebAuthn page — it still sets
    # pending_2fa_user_id, so without this check a POST straight to this route with a
    # valid TOTP code completed the login and stepped around the security key entirely.
    if not totp_is_accepted_for(db, user):
        logger.warning(
            f"Rejected TOTP submission for user {user.username}: the account requires "
            f"WebAuthn as its second factor."
        )
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.TOTP_FAILED,
                user_id=user.id, username=user.username, ip_address=client_ip,
                details={"reason": "webauthn_required_totp_not_accepted"},
            )
        except Exception as e:
            logger.warning(f"Security event logging failed (TOTP_FAILED downgrade): {e}")
        return RedirectResponse(
            url=request.url_for('ui_webauthn_2fa_form'), status_code=status.HTTP_303_SEE_OTHER
        )

    # Per-account limit, checked before the code is even looked at. The per-IP limit
    # alone cannot see a TOTP guessing run spread across a proxy pool, and a 6-digit
    # code is a small enough space that this matters.
    if security_manager.is_username_blocked(user.username):
        logger.warning(
            f"TOTP submission blocked for username '{user.username}' due to the "
            f"distributed rate limit (IP: {client_ip})"
        )
        return RedirectResponse(
            url=f"{request.url_for('ui_login_totp_form')}?error_message="
                f"{quote_plus(_('Too many failed attempts. Please try again later.'))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    decrypted_secret = crud.user.get_decrypted_totp_secret_for_user(user)
    if not decrypted_secret or not security.verify_totp_code(decrypted_secret, totp_code):
        security_manager.record_failure(client_ip, 'totp', username=user.username)
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.TOTP_FAILED,
                user_id=user.id, username=user.username,
                ip_address=client_ip, details={"reason": "invalid_code"}
            )
        except Exception as e:
            logger.warning(f"Security event logging failed (TOTP_FAILED): {e}")
        return RedirectResponse(url=f"{request.url_for('ui_login_totp_form')}?error_message={quote_plus(_("Invalid 2FA code. Please try again."))}", status_code=status.HTTP_303_SEE_OTHER)

    del request.session["pending_2fa_user_id"]

    old_session_data = dict(request.session)
    request.session.clear()
    request.session.update(old_session_data)
    request.session[f"2fa_passed_for_user_{user.id}"] = True

    # The 2FA step is complete, so the token that guarded it is spent. Verification
    # above deliberately did not rotate (see the comment there) to keep retries of a
    # mistyped code working; rotate now that it has succeeded.
    rotate_csrf_token(request)

    crud.user.record_login(db, user)
    # A fresh login is by definition a recently proven password.
    mark_reauthenticated(request, user.id)
    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.TOTP_SUCCESS,
            user_id=user.id, username=user.username,
            ip_address=client_ip
        )
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.LOGIN_SUCCESS,
            user_id=user.id, username=user.username,
            ip_address=client_ip, details={"method": "totp"}
        )
    except Exception as e:
        logger.warning(f"Security event logging failed (TOTP/LOGIN_SUCCESS): {e}")

    access_token_expires = datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token_with_2fa_status(
        username=user.username, is_2fa_completed=True, expires_delta=access_token_expires,
        token_version=user.token_version or 0,
    )

    redirect_url = request.url_for('ui_admin_dashboard') if user.is_admin else request.url_for('ui_dashboard')
    redirect_response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)

    is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"
    redirect_response.set_cookie(
        key="__Host-access_token" if is_secure else "access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=int(access_token_expires.total_seconds()),
        samesite="Lax",
        secure=is_secure,
        path="/"
    )
    return redirect_response

def _csrf_refresh_interval() -> int:
    """
    Seconds until a client should poll /csrf-token/refresh again.

    Two independent clocks bound this, and the tighter one wins:

    * the CSRF token's own life (CSRF_TOKEN_RENEW_AFTER), and
    * the signed session cookie, whose max_age is ACCESS_TOKEN_EXPIRE_MINUTES. The poll
      is also what keeps that sliding cookie alive in a tab nobody is clicking in; miss
      it and the session -- and with it the stored token -- is gone, which surfaces as
      "CSRF token missing from session" rather than as an expiry.

    Half of the tighter one, so a single missed poll is still recoverable.
    """
    session_lifetime = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return max(60, int(min(session_lifetime, CSRF_TOKEN_RENEW_AFTER) * 0.5))


@router.get("/csrf-token/refresh", name="ui_csrf_refresh")
def refresh_csrf_token(request: Request):
    """
    Hand the current session its CSRF token back, renewing it once it is past half life.

    Called from base.html on every page that renders a CSRF form, so it has to stay
    reachable without a login — the login form itself carries a token and is exactly
    the page most likely to sit open long enough to need this.

    Two things it must not do, both of which it used to:

    * **Create a session.** It wrote to `request.session` unconditionally, so any
      anonymous request minted a signed session cookie. Now a caller without an
      established CSRF token gets a 403 and no cookie; there is nothing to refresh
      for a client that never loaded a form.
    * **Rotate blindly.** It replaced the token on every poll without keeping
      `csrf_token_prev`, so a tab that had rendered its form before the poll
      submitted a token the server no longer knew — the failure the rotation
      fallback in verify_csrf_token() exists to prevent. A token still inside
      CSRF_TOKEN_RENEW_AFTER is returned unchanged; an older one is replaced, and
      that goes through the normal rotation so the previous value survives one
      more request.

    Renewal happens at half the token's life, not at the end of it. Waiting for the
    hard expiry left every open form holding a dead token for as long as the gap to
    the next poll, which is exactly the "expired CSRF token" the poll exists to
    prevent. `next_refresh_in` tells the caller when to come back so the schedule is
    derived from the two real lifetimes here rather than guessed in the template.
    """
    from fastapi.responses import JSONResponse

    existing = request.session.get("csrf_token")
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No session to refresh a CSRF token for. Please reload the page.",
        )

    if not csrf_token_needs_renewal(existing):
        return JSONResponse({"csrf_token": existing, "next_refresh_in": _csrf_refresh_interval()})

    rotate_csrf_token(request)
    return JSONResponse({
        "csrf_token": request.session["csrf_token"],
        "next_refresh_in": _csrf_refresh_interval(),
    })

@router.get("/logout", response_class=RedirectResponse, name="ui_logout")
def ui_logout_route(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip),
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
):
    if current_user:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.LOGOUT,
                user_id=current_user.id, username=current_user.username,
                ip_address=client_ip
            )
        except Exception as e:
            logger.warning(f"Security event logging failed (LOGOUT): {e}")
        # The account's live-data and log sockets, in this worker. They were
        # authenticated at their handshake and would otherwise outlive the session:
        # a second tab of this browser kept showing live data after the logout.
        websocket_manager.disconnect_user_threadsafe(current_user.id)

    redirect_response = RedirectResponse(url=str(request.url_for('ui_login_form')), status_code=status.HTTP_303_SEE_OTHER)

    # Determine if we're using secure cookies
    is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"

    # Delete BOTH cookie variants, not just the one this deployment issues.
    # _get_access_token() accepts "__Host-access_token" or "access_token", so clearing
    # only the secure name leaves a legacy cookie authenticating the next request — the
    # user believes they logged out but the session continues. It also matters the other
    # way round: a legacy cookie planted over plain HTTP on a sibling host (the __Host-
    # prefix prevents that only for the secure variant) would otherwise survive logout
    # and silently take over the session afterwards.
    if is_secure:
        redirect_response.delete_cookie(
            key="__Host-access_token",
            path="/",
            secure=True,
            httponly=True,
            samesite="Lax"
        )
    redirect_response.delete_cookie(
        key="access_token",
        path="/",
        httponly=True,
        samesite="Lax"
    )

    # Clear all session data
    if current_user:
        session_keys_to_clear = [
            f"2fa_passed_for_user_{current_user.id}",
            "pending_2fa_user_id",
            "user_id",
            "username",
            "is_admin"
        ]
        for key in session_keys_to_clear:
            if key in request.session:
                del request.session[key]

    # Clear any remaining session data
    request.session.clear()

    return redirect_response


# --- Password Reset ---

@router.get("/forgot-password", response_class=HTMLResponse, name="ui_forgot_password_form")
def ui_forgot_password_form_route(
    request: Request,
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
):
    """Display the forgot password form."""
    if current_user:
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse(request, "forgot_password.html", {
        **common_vars,
        "page_title": N_("Forgot Password"),
        "csrf_token": csrf_token
    })


@router.post("/forgot-password", response_class=HTMLResponse, name="ui_forgot_password_submit")
def ui_forgot_password_submit_route(
    request: Request,
    background_tasks: "BackgroundTasks",
    email: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Handle forgot password form submission."""
    _ = get_translator(request)
    from app.notifications import send_password_reset_email
    from app.security_events import security_event_logger, SecurityEventType, SecurityEventSeverity

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        forgot_form_url = str(request.url_for('ui_forgot_password_form'))
        return RedirectResponse(url=f"{forgot_form_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    # Check rate limiting - blocked IPs are blocked for all auth types
    if security_manager.is_blocked(client_ip):
        logger.warning(f"Password reset attempt from blocked IP {client_ip}")
        # Still show generic message to prevent enumeration
        common_vars = get_common_template_vars(request, None)
        return templates.TemplateResponse(request, "forgot_password_sent.html", {
            **common_vars,
            "page_title": N_("Check Your Email")
        })

    # The enumeration-safe message is rendered by forgot_password_sent.html, which this
    # handler returns on every path — existing user, unknown user, passwordless-only
    # account. It used to be duplicated here as a local that nothing read; the template's
    # copy is the one that ships, and unlike this one it goes through gettext.

    # Normalize email
    email = email.strip().lower()

    # Look up user by email
    user = crud.user.get_user_by_email(db, email=email)

    # Always show success page to prevent enumeration, but only send email if user exists
    if user and user.is_active:
        # Check if user has passwordless-only WebAuthn (no password login allowed)
        _webauthn_modes = {
            row.usage_mode
            for row in db.query(models_db.WebAuthnCredential.usage_mode).filter(
                models_db.WebAuthnCredential.user_id == user.id,
                models_db.WebAuthnCredential.is_active == True,
                models_db.WebAuthnCredential.usage_mode.in_(['passwordless', '2fa'])
            ).all()
        }
        has_passwordless_webauthn = 'passwordless' in _webauthn_modes
        has_password_2fa = user.is_totp_enabled or '2fa' in _webauthn_modes

        # If user has passwordless WebAuthn but no password-based 2FA, they can't use password reset
        # (their account is passwordless-only). Still show generic message.
        if has_passwordless_webauthn and not has_password_2fa:
            logger.info(f"Password reset requested for passwordless-only account: {email}")
            # Log the event but don't send email (passwordless accounts can't reset password)
            try:
                security_event_logger.log_event(
                    db=db,
                    event_type=SecurityEventType.PASSWORD_RESET_REQUESTED,
                    severity=SecurityEventSeverity.INFO,
                    user_id=user.id,
                    username=user.username,
                    ip_address=client_ip,
                    details={"email": email, "reason": "passwordless_only_account"}
                )
            except Exception as e:
                logger.warning(f"Security event logging failed (PASSWORD_RESET_REQUESTED): {e}")
        else:
            # Generate password reset token
            token = crud.user.set_password_reset_token(db, user)
            # Not request.url_for(): the link is mailed, so its host must come from
            # configuration and not from the request's Host header. See
            # app/utils/urls.py.
            reset_link = external_url_for(request, 'ui_reset_password_form', token=token)

            # Extract user data before background task (to avoid detached instance error)
            user_email = user.email
            user_display_name = user.full_name or user.username

            # Send password reset email in background (uses default locale since browser language not available in background)
            background_tasks.add_task(send_password_reset_email, user_email, user_display_name, settings.BABEL_DEFAULT_LOCALE, reset_link)

            logger.info(f"Password reset email queued for user: {user.username}")

            # Log security event
            try:
                security_event_logger.log_event(
                    db=db,
                    event_type=SecurityEventType.PASSWORD_RESET_REQUESTED,
                    severity=SecurityEventSeverity.INFO,
                    user_id=user.id,
                    username=user.username,
                    ip_address=client_ip,
                    details={"email": email}
                )
            except Exception as e:
                logger.warning(f"Security event logging failed (PASSWORD_RESET_REQUESTED): {e}")
    else:
        # User doesn't exist or is inactive - log attempt but show same message
        logger.info(f"Password reset requested for non-existent or inactive email: {email}")

    # Rate-limit every reset attempt (valid user or not) against the IP so a single
    # IP cannot spam reset emails for real accounts indefinitely.
    security_manager.record_failure(client_ip, 'login')

    common_vars = get_common_template_vars(request, None)
    return templates.TemplateResponse(request, "forgot_password_sent.html", {
        **common_vars,
        "page_title": N_("Check Your Email")
    })


def _reset_token_is_expired(user: models_db.User) -> bool:
    """
    Whether this user's password reset token is past its deadline.

    A missing deadline counts as expired. crud.user.set_password_reset_token() always
    writes one, so a row carrying a token with no expiry is not something the current
    code can produce — but "no deadline" previously meant the expiry branch was skipped
    entirely, i.e. a token that never expires. For the one credential whose whole job is
    to replace a password, the safe reading of a missing deadline is "too old", not
    "eternally valid".

    Shared by the form and the submit route so the two cannot drift: a check that lives
    only on the GET is not a check at all, since the POST carries the token itself.
    """
    expires_at = user.password_reset_token_expires_at
    if expires_at is None:
        return True
    # Handle naive datetimes from SQLite (written as, and therefore assumed, UTC).
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    return datetime.datetime.now(datetime.timezone.utc) > expires_at


@router.get("/reset-password/{token}", response_class=HTMLResponse, name="ui_reset_password_form")
def ui_reset_password_form_route(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
    current_user: Optional[models_db.User] = Depends(get_user_from_request_cookie)
):
    """Display the password reset form."""
    if current_user:
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)

    # Validate token
    user = crud.user.get_user_by_password_reset_token(db, token=token)

    if not user:
        common_vars = get_common_template_vars(request, None)
        return templates.TemplateResponse(request, "reset_password_invalid.html", {
            **common_vars,
            "page_title": N_("Invalid Reset Link"),
            "error_reason": "invalid"
        })

    if _reset_token_is_expired(user):
        crud.user.clear_password_reset_token(db, user)
        common_vars = get_common_template_vars(request, None)
        return templates.TemplateResponse(request, "reset_password_invalid.html", {
            **common_vars,
            "page_title": N_("Reset Link Expired"),
            "error_reason": "expired"
        })

    common_vars = get_common_template_vars(request, None)
    csrf_token = get_csrf_token(request)
    return templates.TemplateResponse(request, "reset_password.html", {
        **common_vars,
        "page_title": N_("Set New Password"),
        "csrf_token": csrf_token,
        "token": token,
        "username": user.username
    })


@router.post("/reset-password/{token}", response_class=HTMLResponse, name="ui_reset_password_submit")
def ui_reset_password_submit_route(
    request: Request,
    token: str,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Handle password reset form submission."""
    _ = get_translator(request)
    from app.security_events import security_event_logger, SecurityEventType, SecurityEventSeverity

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        reset_form_url = str(request.url_for('ui_reset_password_form', token=token))
        return RedirectResponse(url=f"{reset_form_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    # Validate token
    user = crud.user.get_user_by_password_reset_token(db, token=token)

    if not user:
        common_vars = get_common_template_vars(request, None)
        return templates.TemplateResponse(request, "reset_password_invalid.html", {
            **common_vars,
            "page_title": N_("Invalid Reset Link"),
            "error_reason": "invalid"
        })

    if _reset_token_is_expired(user):
        crud.user.clear_password_reset_token(db, user)
        common_vars = get_common_template_vars(request, None)
        return templates.TemplateResponse(request, "reset_password_invalid.html", {
            **common_vars,
            "page_title": N_("Reset Link Expired"),
            "error_reason": "expired"
        })

    # Validate passwords match
    if new_password != confirm_password:
        common_vars = get_common_template_vars(request, None)
        new_csrf_token = get_csrf_token(request)
        return templates.TemplateResponse(request, "reset_password.html", {
            **common_vars,
            "page_title": N_("Set New Password"),
            "csrf_token": new_csrf_token,
            "token": token,
            "username": user.username,
            "error_message": N_("Passwords do not match.")
        })

    # Validate password strength and policy consistency with API registration
    try:
        models_api.validate_password_strength(new_password)
    except ValueError as e:
        common_vars = get_common_template_vars(request, None)
        new_csrf_token = get_csrf_token(request)
        return templates.TemplateResponse(request, "reset_password.html", {
            **common_vars,
            "page_title": N_("Set New Password"),
            "csrf_token": new_csrf_token,
            "token": token,
            "username": user.username,
            "error_message": str(e)
        })

    # Reset the password
    crud.user.reset_user_password(db, user, new_password)

    logger.info(f"Password reset completed for user: {user.username}")

    # Log security event
    try:
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.PASSWORD_RESET_COMPLETED,
            severity=SecurityEventSeverity.INFO,
            user_id=user.id,
            username=user.username,
            ip_address=client_ip,
            details={}
        )
    except Exception as e:
        logger.warning(f"Security event logging failed (PASSWORD_RESET_COMPLETED): {e}")

    common_vars = get_common_template_vars(request, None)
    return templates.TemplateResponse(request, "reset_password_success.html", {
        **common_vars,
        "page_title": N_("Password Reset Successful")
    })
