"""
WebAuthn/FIDO2 UI routes.
"""
from fastapi import APIRouter, Depends, Request, HTTPException, status, Form
from fastapi.responses import RedirectResponse, JSONResponse, HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.dependencies import require_current_user_from_cookie_fully_authenticated, get_client_ip
from app.models.db import User, WebAuthnCredential
from app.utils.webauthn_helper import WebAuthnHelper
from app.security_events import security_event_logger, SecurityEventType, SecurityEventSeverity
from app.security_manager import security_manager
from app.utils.i18n_markers import N_
from app.routers.ui import get_common_template_vars, get_translator, templates
from app.config import get_settings
from app.csrf_protection import verify_csrf_token
from app.utils.two_factor import SecondFactor, required_second_factor
from app.utils.step_up import has_recent_reauth, mark_reauthenticated
from app import crud
import datetime
from pydantic import BaseModel
from typing import Dict, Any, Optional
import base64

router = APIRouter()
settings = get_settings()

# Initialize WebAuthn helper
webauthn_helper = WebAuthnHelper(
    rp_id=settings.WEBAUTHN_RP_ID,
    rp_name=settings.WEBAUTHN_RP_NAME,
    origin=settings.WEBAUTHN_ORIGIN
)


class RegistrationRequest(BaseModel):
    credential_name: str
    usage_mode: str = 'passwordless'  # 'passwordless' or '2fa'
    csrf_token: str


class RegistrationComplete(BaseModel):
    credential_name: str
    usage_mode: str = 'passwordless'  # 'passwordless' or '2fa'
    credential: Dict[str, Any]
    csrf_token: str
    # credProps.rk as reported by the browser: True if the authenticator stored the
    # credential on itself. None when the extension was not requested, not supported or
    # not answered — which is common enough that it must stay a distinct value rather
    # than collapsing into False. Only ever narrows what the server does: an
    # unrecognised credential is named in allowCredentials, never hidden.
    resident_key: Optional[bool] = None


class AuthenticationRequest(BaseModel):
    csrf_token: str


class AuthenticationComplete(BaseModel):
    credential: Dict[str, Any]
    csrf_token: str


@router.get("/webauthn/register")
def ui_webauthn_register(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """Display WebAuthn registration page."""
    context = get_common_template_vars(request, current_user)
    context.update({
        "page_title": N_("Register Security Key")
    })

    return templates.TemplateResponse(request, "webauthn_register.html", context)


@router.post("/webauthn/register/begin")
def ui_webauthn_register_begin(
    request: Request,
    data: RegistrationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """Start WebAuthn registration process."""
    _ = get_translator(request)
    verify_csrf_token(request, data.csrf_token, rotate_token=False)

    # Step-up required. This is the chain the audit called out: brief access to a
    # logged-in session was enough to register a passwordless credential, which is a
    # permanent second way in that does not depend on the password and survives a
    # password change. JSON endpoint, so the answer is a machine-readable 403 rather
    # than a redirect — the client shows the confirm-password page itself.
    if not has_recent_reauth(request, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_("Please confirm your password before registering a security key."),
        )

    # Get user's existing credentials
    existing_credentials = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == current_user.id,
        WebAuthnCredential.is_active == True
    ).all()

    # Normalise once, here, and remember the decision: the UV requirement baked into
    # the options below depends on it, and /complete used to take the client's word for
    # it a second time. Beginning as '2fa' (user_verification PREFERRED) and completing
    # as 'passwordless' therefore stored a credential in the stronger role that had
    # never been asked to prove it could do UV.
    usage_mode = data.usage_mode if data.usage_mode in ('passwordless', '2fa') else 'passwordless'

    # Generate registration options. A passwordless credential must be UV-capable,
    # because the passwordless login rejects assertions without the UV flag, and
    # discoverable, because that login has no user to look it up by — see
    # ui_webauthn_auth_begin for what naming credentials instead used to cost.
    options = webauthn_helper.generate_registration_options(
        user=current_user,
        existing_credentials=existing_credentials,
        require_user_verification=(usage_mode == 'passwordless'),
        require_discoverable=(usage_mode == 'passwordless'),
    )

    # Store challenge in session (it's now wrapped in publicKey)
    challenge_b64 = options['publicKey']['challenge']
    request.session['webauthn_register_challenge'] = challenge_b64
    request.session['webauthn_register_user_id'] = current_user.id
    request.session['webauthn_register_usage_mode'] = usage_mode

    return JSONResponse(content=options)


@router.post("/webauthn/register/complete")
def ui_webauthn_register_complete(
    request: Request,
    data: RegistrationComplete,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    """Complete WebAuthn registration."""
    _ = get_translator(request)
    verify_csrf_token(request, data.csrf_token, rotate_token=False)

    # Verify challenge from session
    expected_challenge_b64 = request.session.get('webauthn_register_challenge')
    stored_user_id = request.session.get('webauthn_register_user_id')
    # The role this ceremony was started for. Taken from the session, never from the
    # request body — see /begin.
    stored_usage_mode = request.session.get('webauthn_register_usage_mode')

    if not expected_challenge_b64 or stored_user_id != current_user.id or not stored_usage_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Invalid or expired registration session")
        )

    if data.usage_mode != stored_usage_mode:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Registration was started for a different credential type. Please start over."),
        )

    try:
        # Convert base64url challenge to bytes
        expected_challenge = base64.urlsafe_b64decode(expected_challenge_b64 + '==')

        # Verify the registration response
        verified_credential = webauthn_helper.verify_registration_response(
            credential=data.credential,
            expected_challenge=expected_challenge
        )

        # Only a passwordless credential is ever looked up without a user, so only that
        # role has anything to gain from being discoverable — and only that role asked
        # for credProps in the first place. Recording the client's claim for a 2FA
        # credential would be storing an answer to a question nobody asked.
        is_discoverable = data.resident_key if stored_usage_mode == 'passwordless' else None

        # Store credential in database
        new_credential = WebAuthnCredential(
            user_id=current_user.id,
            credential_id=verified_credential['credential_id'],
            public_key=verified_credential['credential_public_key'],
            sign_count=verified_credential['sign_count'],
            credential_name=data.credential_name,
            usage_mode=stored_usage_mode,
            is_discoverable=is_discoverable,
            created_at=datetime.datetime.now(datetime.timezone.utc),
            is_active=True
        )

        db.add(new_credential)

        # Enable WebAuthn for user if first credential
        if not current_user.webauthn_enabled:
            current_user.webauthn_enabled = True

        db.commit()

        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_REGISTERED,
                user_id=current_user.id, username=current_user.username,
                ip_address=client_ip, details={"credential_name": data.credential_name}
            )
        except Exception:
            pass

        # Clear session challenge
        request.session.pop('webauthn_register_challenge', None)
        request.session.pop('webauthn_register_user_id', None)
        request.session.pop('webauthn_register_usage_mode', None)

        return JSONResponse(content={"success": True})

    except Exception as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_FAILED,
                severity=SecurityEventSeverity.ERROR,
                user_id=current_user.id, username=current_user.username,
                ip_address=client_ip, details={"error": str(e), "stage": "registration"}
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Registration failed. Please try again.")
        )


@router.get("/webauthn/login")
def ui_webauthn_login(
    request: Request,
    db: Session = Depends(get_db)
):
    """Display WebAuthn login page."""
    context = get_common_template_vars(request, None)
    context.update({
        "page_title": N_("WebAuthn Login")
    })

    return templates.TemplateResponse(request, "webauthn_login.html", context)


@router.post("/webauthn/auth/begin")
def ui_webauthn_auth_begin(
    request: Request,
    data: AuthenticationRequest,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Start WebAuthn authentication process."""
    try:
        verify_csrf_token(request, data.csrf_token, rotate_token=False)
    except HTTPException as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.CSRF_VIOLATION,
                ip_address=client_ip, details={"endpoint": "webauthn_auth_begin", "reason": e.detail}
            )
        except Exception:
            pass
        raise e

    # This endpoint is reachable by anyone: passwordless login has not identified a user
    # yet, and the only gate is a CSRF token that GET /webauthn/login hands to every
    # visitor. Whatever it returns is therefore public.
    #
    # It used to return an allowCredentials list built from *every* passwordless
    # credential on the server, so one request enumerated the credential id of every
    # passkey user. Discoverable credentials do not need to be named at all — the
    # authenticator finds them on its own — so they are left out entirely.
    #
    # Credentials registered before registration asked for a resident key
    # (is_discoverable NULL) and the rare authenticator that refused one (False) still
    # have to be named, or their owners cannot sign in. That residue is what the
    # migration in e6f7a8b9c0d1 exists to drain: it only ever shrinks, and it is the
    # conservative side of the trade — an account with a passwordless key and no second
    # factor has no password login to fall back on
    # (app/utils/two_factor.password_login_is_disabled), so guessing wrong here would
    # lock it out of its own server for good.
    legacy_credentials = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.is_active == True,
        WebAuthnCredential.usage_mode == 'passwordless',
        WebAuthnCredential.is_discoverable.isnot(True),
    ).all()

    # Deliberately not gated on "are there any credentials at all" any more. That check
    # answered, to an unauthenticated caller, whether this server has passkey users —
    # and with discoverable credentials there is nothing to count in the first place.
    # An assertion for a credential that does not exist fails at /complete, which is
    # where a wrong credential belongs.

    # Generate authentication options. Passwordless: demand user verification, so the
    # assertion carries PIN or biometrics rather than a bare touch.
    options = webauthn_helper.generate_authentication_options(
        user_credentials=legacy_credentials,
        require_user_verification=True,
    )

    # Store challenge in session (it's now wrapped in publicKey)
    challenge_b64 = options['publicKey']['challenge']
    request.session['webauthn_auth_challenge'] = challenge_b64

    return JSONResponse(content=options)


@router.post("/webauthn/auth/complete")
def ui_webauthn_auth_complete(
    request: Request,
    data: AuthenticationComplete,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Complete WebAuthn authentication."""
    _ = get_translator(request)
    try:
        verify_csrf_token(request, data.csrf_token, rotate_token=False)
    except HTTPException as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.CSRF_VIOLATION,
                ip_address=client_ip, details={"endpoint": "webauthn_auth_complete", "reason": e.detail}
            )
        except Exception:
            pass
        raise e

    # Verify challenge from session
    expected_challenge_b64 = request.session.get('webauthn_auth_challenge')

    if not expected_challenge_b64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Invalid or expired authentication session")
        )

    try:
        # Find credential by ID - convert from base64url to hex
        # The browser sends credential.id as base64url, but we store it as hex
        credential_id_b64url = data.credential['id']

        # Convert base64url to bytes, then to hex
        # Add padding if needed for base64url decoding
        padding = '=' * (4 - len(credential_id_b64url) % 4) if len(credential_id_b64url) % 4 else ''
        credential_id_bytes = base64.urlsafe_b64decode(credential_id_b64url + padding)
        credential_id_hex = credential_id_bytes.hex()

        credential = db.query(WebAuthnCredential).filter(
            WebAuthnCredential.credential_id == credential_id_hex,
            WebAuthnCredential.is_active == True,
            WebAuthnCredential.usage_mode == 'passwordless'
        ).first()

        if not credential:
            # An unknown credential id is a guess, exactly as an unknown API key or a
            # wrong password is, and this is the endpoint where a guess actually costs
            # something now that /begin no longer hands the ids out. It was the only
            # authentication path that never recorded a failure, so it could be hammered
            # indefinitely without the IP block ever noticing.
            security_manager.record_failure(client_ip, 'login')
            try:
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.WEBAUTHN_FAILED,
                    severity=SecurityEventSeverity.WARNING,
                    ip_address=client_ip,
                    details={"reason": "unknown_credential", "stage": "passwordless_auth"},
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_("Unknown credential or not configured for passwordless login")
            )

        # Get associated user
        user = db.query(User).filter(User.id == credential.user_id).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_("User account is inactive")
            )

        # Convert base64url challenge to bytes
        expected_challenge = base64.urlsafe_b64decode(expected_challenge_b64 + '==')

        # Verify authentication response. require_user_verification: this assertion is
        # the entire login, so a bare presence touch must not be enough.
        verification = webauthn_helper.verify_authentication_response(
            credential=data.credential,
            expected_challenge=expected_challenge,
            credential_public_key=bytes.fromhex(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )

        # Update credential sign count and last used
        credential.sign_count = verification['new_sign_count']
        credential.last_used_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        # A passkey replaces the *password*, not the second factor.
        #
        # This handler used to set is_2fa_completed=True unconditionally, so an
        # account with a passkey and TOTP enabled was reachable with the passkey
        # alone. That is the same hole as N-6, which was closed for the TOTP submit
        # route: the ranking moved into app.utils.two_factor so no login path could
        # disagree about what an account requires — and this fourth path never asked.
        required = required_second_factor(db, user)
        if required != SecondFactor.NONE:
            request.session["pending_2fa_user_id"] = user.id
            request.session.pop('webauthn_auth_challenge', None)

            try:
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.WEBAUTHN_SUCCESS,
                    user_id=user.id, username=user.username, ip_address=client_ip,
                    details={"credential_name": credential.credential_name or "Unknown",
                             "stage": "passwordless_first_factor",
                             "second_factor_required": required.value},
                )
            except Exception:
                pass

            next_route = (
                'ui_webauthn_2fa_form' if required == SecondFactor.WEBAUTHN
                else 'ui_login_totp_form'
            )
            return JSONResponse(content={
                "success": True,
                "redirect_url": str(request.url_for(next_route)),
            })

        crud.user.record_login(db, user)
        mark_reauthenticated(request, user.id)

        # Create session
        request.session["user_id"] = user.id
        request.session["username"] = user.username
        request.session["is_admin"] = user.is_admin
        request.session[f"2fa_passed_for_user_{user.id}"] = True

        # Create JWT access token
        from app import security

        access_token_expires = datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = security.create_access_token_with_2fa_status(
            username=user.username, is_2fa_completed=True, expires_delta=access_token_expires,
            token_version=user.token_version or 0,
        )

        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_SUCCESS,
                user_id=user.id, username=user.username,
                ip_address=client_ip, details={"credential_name": credential.credential_name or "Unknown"}
            )
        except Exception:
            pass

        # Clear session challenge
        request.session.pop('webauthn_auth_challenge', None)

        # Create JSON response with JWT cookie
        response = JSONResponse(content={
            "success": True,
            "redirect_url": str(request.url_for('ui_dashboard'))
        })

        # Set secure cookie with __Host- prefix for additional security
        is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"
        response.set_cookie(
            key="__Host-access_token" if is_secure else "access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=int(access_token_expires.total_seconds()),
            samesite="Lax",
            secure=is_secure,
            path="/"
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_FAILED,
                ip_address=client_ip, details={"reason": str(e)}
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Authentication failed. Please try again.")
        )


@router.post("/webauthn/delete/{credential_id}")
def ui_webauthn_delete(
    request: Request,
    credential_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_current_user_from_cookie_fully_authenticated),
    client_ip: str = Depends(get_client_ip)
):
    """Delete a WebAuthn credential."""
    _ = get_translator(request)
    verify_csrf_token(request, csrf_token)

    if not has_recent_reauth(request, current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_("Please confirm your password before removing a security key."),
        )

    credential = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.id == credential_id,
        WebAuthnCredential.user_id == current_user.id
    ).first()

    if not credential:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_("Credential not found")
        )

    credential_name = credential.credential_name

    # Delete credential
    db.delete(credential)

    # Disable WebAuthn if no more credentials
    remaining_credentials = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == current_user.id,
        WebAuthnCredential.id != credential_id
    ).count()

    if remaining_credentials == 0:
        current_user.webauthn_enabled = False

    db.commit()

    try:
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.WEBAUTHN_REMOVED,
            user_id=current_user.id, username=current_user.username,
            ip_address=client_ip, details={"credential_name": credential_name}
        )
    except Exception:
        pass

    return RedirectResponse(
        url=f"{request.url_for('ui_profile_page')}?tab=webauthn",
        status_code=status.HTTP_303_SEE_OTHER
    )


# WebAuthn 2FA Routes (for Two-Factor Authentication after password login)

@router.get("/login/webauthn", response_class=HTMLResponse, name="ui_webauthn_2fa_form")
async def ui_webauthn_2fa_form(
    request: Request,
    db: Session = Depends(get_db)
):
    """Display WebAuthn 2FA verification page."""
    from app.dependencies import get_user_from_request_cookie
    from app.routers.ui import get_common_template_vars

    pending_user_id = request.session.get("pending_2fa_user_id")
    current_user = await get_user_from_request_cookie(request, db)

    if not pending_user_id and not current_user:
        return RedirectResponse(url=request.url_for('ui_login_form'), status_code=status.HTTP_303_SEE_OTHER)

    if current_user and request.session.get(f"2fa_passed_for_user_{current_user.id}"):
        return RedirectResponse(url=request.url_for('ui_dashboard'), status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)

    user_for_display = None
    if pending_user_id:
        user_for_display = db.query(User).filter(User.id == pending_user_id).first()
    elif current_user:
        user_for_display = current_user

    username_for_display = user_for_display.username if user_for_display else ""

    return templates.TemplateResponse(request, "login_webauthn_2fa.html", {
        **common_vars,
        "request": request,
        "page_title": N_("Two-Factor Authentication"),
        "username_for_display": username_for_display,
    })


@router.post("/login/webauthn/begin", name="ui_webauthn_2fa_begin")
async def ui_webauthn_2fa_begin(
    request: Request,
    data: AuthenticationRequest,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Start WebAuthn 2FA authentication process."""
    _ = get_translator(request)
    try:
        verify_csrf_token(request, data.csrf_token, rotate_token=False)
    except HTTPException as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.CSRF_VIOLATION,
                ip_address=client_ip, details={"endpoint": "webauthn_2fa_begin", "reason": e.detail}
            )
        except Exception:
            pass
        raise e

    from app.dependencies import get_user_from_request_cookie
    from app import crud

    pending_user_id = request.session.get("pending_2fa_user_id")
    current_user = await get_user_from_request_cookie(request, db)

    user = None
    if pending_user_id:
        user = crud.user.get_user_by_id(db, user_id=pending_user_id)
    elif current_user:
        user = current_user

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("No pending 2FA session")
        )

    # Get user's 2FA WebAuthn credentials
    credentials_2fa = db.query(WebAuthnCredential).filter(
        WebAuthnCredential.user_id == user.id,
        WebAuthnCredential.is_active == True,
        WebAuthnCredential.usage_mode == '2fa'
    ).all()

    if not credentials_2fa:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("No 2FA WebAuthn credentials registered")
        )

    # Generate authentication options
    options = webauthn_helper.generate_authentication_options(
        user_credentials=credentials_2fa
    )

    # Store challenge in session
    challenge_b64 = options['publicKey']['challenge']
    request.session['webauthn_2fa_challenge'] = challenge_b64

    return JSONResponse(content=options)


@router.post("/login/webauthn/complete", name="ui_webauthn_2fa_complete")
async def ui_webauthn_2fa_complete(
    request: Request,
    data: AuthenticationComplete,
    db: Session = Depends(get_db),
    client_ip: str = Depends(get_client_ip)
):
    """Complete WebAuthn 2FA authentication."""
    _ = get_translator(request)
    try:
        verify_csrf_token(request, data.csrf_token, rotate_token=False)
    except HTTPException as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.CSRF_VIOLATION,
                ip_address=client_ip, details={"endpoint": "webauthn_2fa_complete", "reason": e.detail}
            )
        except Exception:
            pass
        raise e

    from app.dependencies import get_user_from_request_cookie
    from app import crud, security
    from app.config import get_settings

    settings = get_settings()

    # Verify challenge from session
    expected_challenge_b64 = request.session.get('webauthn_2fa_challenge')

    if not expected_challenge_b64:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Invalid or expired authentication session")
        )

    pending_user_id = request.session.get("pending_2fa_user_id")
    current_user = await get_user_from_request_cookie(request, db)

    user = None
    if pending_user_id:
        user = crud.user.get_user_by_id(db, user_id=pending_user_id)
    elif current_user:
        user = current_user

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=_("User account is inactive")
        )

    try:
        # Find credential by ID - convert from base64url to hex
        # The browser sends credential.id as base64url, but we store it as hex
        credential_id_b64url = data.credential['id']

        # Convert base64url to bytes, then to hex
        # Add padding if needed for base64url decoding
        padding = '=' * (4 - len(credential_id_b64url) % 4) if len(credential_id_b64url) % 4 else ''
        credential_id_bytes = base64.urlsafe_b64decode(credential_id_b64url + padding)
        credential_id_hex = credential_id_bytes.hex()

        credential = db.query(WebAuthnCredential).filter(
            WebAuthnCredential.credential_id == credential_id_hex,
            WebAuthnCredential.is_active == True,
            WebAuthnCredential.user_id == user.id,
            WebAuthnCredential.usage_mode == '2fa'
        ).first()

        if not credential:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_("Unknown credential or not configured for 2FA")
            )

        # Convert base64url challenge to bytes
        expected_challenge = base64.urlsafe_b64decode(expected_challenge_b64 + '==')

        # Verify authentication response
        verification = webauthn_helper.verify_authentication_response(
            credential=data.credential,
            expected_challenge=expected_challenge,
            credential_public_key=bytes.fromhex(credential.public_key),
            credential_current_sign_count=credential.sign_count
        )

        # Update credential sign count and last used
        credential.sign_count = verification['new_sign_count']
        credential.last_used_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()

        crud.user.record_login(db, user)
        mark_reauthenticated(request, user.id)

        # Clear pending 2FA session
        if "pending_2fa_user_id" in request.session:
            del request.session["pending_2fa_user_id"]

        # Regenerate session after successful 2FA to prevent session fixation
        old_session_data = dict(request.session)
        request.session.clear()
        request.session.update(old_session_data)
        request.session[f"2fa_passed_for_user_{user.id}"] = True

        # Create access token
        access_token_expires = datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = security.create_access_token_with_2fa_status(
            username=user.username, is_2fa_completed=True, expires_delta=access_token_expires,
            token_version=user.token_version or 0,
        )

        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_SUCCESS,
                user_id=user.id, username=user.username,
                ip_address=client_ip, details={"credential_name": credential.credential_name or "Unknown"}
            )
        except Exception:
            pass

        # Clear session challenge
        request.session.pop('webauthn_2fa_challenge', None)

        # Determine redirect URL
        redirect_url = str(request.url_for('ui_admin_dashboard') if user.is_admin else request.url_for('ui_dashboard'))

        # Create response with cookie
        response_data = {
            "success": True,
            "redirect_url": redirect_url
        }

        response = JSONResponse(content=response_data)

        # Set access token cookie
        is_secure = settings.FORCE_SECURE_COOKIES or request.url.scheme == "https"
        response.set_cookie(
            key="__Host-access_token" if is_secure else "access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=int(access_token_expires.total_seconds()),
            samesite="Lax",
            secure=is_secure,
            path="/"
        )

        return response

    except HTTPException:
        raise
    except Exception as e:
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.WEBAUTHN_FAILED,
                ip_address=client_ip, details={"reason": str(e)}
            )
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_("Authentication failed. Please try again.")
        )
