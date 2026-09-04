from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from pydantic import ValidationError

from app.database import get_db
from app import crud
from app.models import api as models_api, db as models_db
from . import templates, get_common_template_vars, get_translator
from app.dependencies import require_admin_user_from_cookie
from app.csrf_protection import verify_csrf_token
from app.utils.crypto import decrypt_data

router = APIRouter()

@router.get("", response_class=HTMLResponse, name="ui_manage_autoprovision_profiles")
def ui_manage_autoprovision_profiles_route(
    request: Request,
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    common_vars = get_common_template_vars(request, current_admin)
    profiles = crud.autoprovision.get_all_auto_provision_profiles(db, limit=1000)
    return templates.TemplateResponse(request, "autoprovision_management.html", {
        **common_vars,
        "profiles": profiles,
        "page_title": "Auto-Provisioning Management"
    })

@router.get("/add", response_class=HTMLResponse, name="ui_add_autoprovision_profile_form")
def ui_add_autoprovision_profile_form_route(
    request: Request,
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    common_vars = get_common_template_vars(request, current_admin)
    return templates.TemplateResponse(request, "edit_autoprovision_profile.html", {
        **common_vars,
        "profile_to_edit": None,
        "page_title": "Add New Provisioning Profile",
        "form_action_url": request.url_for('ui_add_autoprovision_profile_submit')
    })

@router.post("/add", response_class=RedirectResponse, name="ui_add_autoprovision_profile_submit")
def ui_add_autoprovision_profile_submit_route(
    request: Request,
    ap_key: str = Form(...),
    target_vehicle_id: str = Form(...),
    target_server_password: str = Form(...),
    target_vehicle_name: str = Form(None),
    target_module_password: str = Form(None),
    is_active: bool = Form(True),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    redirect_url_on_error = str(request.url_for('ui_add_autoprovision_profile_form'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)
    if crud.autoprovision.get_auto_provision_profile(db, ap_key):
        # Raw form input: AutoProvisionProfileCreate validates ap_key below, not here.
        msg = quote_plus(f"Provisioning key '{ap_key}' already exists.")
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)

    try:
        profile_in = models_api.AutoProvisionProfileCreate(
            ap_key=ap_key,
            target_vehicle_id=target_vehicle_id,
            target_server_password=target_server_password,
            target_vehicle_name=target_vehicle_name,
            target_module_password=target_module_password,
            is_active=is_active
        )
    except ValidationError as e:
        error_detail = f"{e.errors()['loc'].capitalize()}: {e.errors()['msg']}"
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(str(error_detail))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.autoprovision.create_auto_provision_profile(db, profile_in, owner_id=current_admin.id)
    return RedirectResponse(url=f"{request.url_for('ui_manage_autoprovision_profiles')}?success_message={quote_plus(_("Profile '%(key)s' created successfully.") % {'key': ap_key})}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/{profile_id}/edit", response_class=HTMLResponse, name="ui_edit_autoprovision_profile_form")
def ui_edit_autoprovision_profile_form_route(
    request: Request, profile_id: int, db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    common_vars = get_common_template_vars(request, current_admin)
    profile_to_edit = crud.autoprovision.get_auto_provision_profile_by_id(db, profile_id)
    if not profile_to_edit:
        return RedirectResponse(url=f"{request.url_for('ui_manage_autoprovision_profiles')}?error_message={quote_plus(_("Profile not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    
    try:
        server_pw_display = decrypt_data(profile_to_edit.target_server_password)
    except Exception:
        server_pw_display = ""
    try:
        module_pw_display = decrypt_data(profile_to_edit.target_module_password) if profile_to_edit.target_module_password else ""
    except Exception:
        module_pw_display = ""

    return templates.TemplateResponse(request, "edit_autoprovision_profile.html", {
        **common_vars,
        "profile_to_edit": profile_to_edit,
        "server_pw_display": server_pw_display,
        "module_pw_display": module_pw_display,
        "page_title": f"Edit Profile: {profile_to_edit.ap_key}",
        "form_action_url": request.url_for('ui_edit_autoprovision_profile_submit', profile_id=profile_id)
    })

@router.post("/{profile_id}/edit", response_class=RedirectResponse, name="ui_edit_autoprovision_profile_submit")
def ui_edit_autoprovision_profile_submit_route(
    request: Request, profile_id: int,
    ap_key: str = Form(...),
    target_vehicle_id: str = Form(...),
    target_server_password: str = Form(...),
    target_vehicle_name: str = Form(None),
    target_module_password: str = Form(None),
    is_active: bool = Form(False),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    profile_db = crud.autoprovision.get_auto_provision_profile_by_id(db, profile_id)
    redirect_url_on_error = str(request.url_for('ui_edit_autoprovision_profile_form', profile_id=profile_id))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    if not profile_db:
        return RedirectResponse(url=f"{request.url_for('ui_manage_autoprovision_profiles')}?error_message={quote_plus(_("Profile not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    if ap_key != profile_db.ap_key and crud.autoprovision.get_auto_provision_profile(db, ap_key):
        # Raw form input, same as the add route above.
        msg = quote_plus(f"Provisioning key '{ap_key}' already exists.")
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)
    
    try:
        profile_in = models_api.AutoProvisionProfileCreate(
            ap_key=ap_key,
            target_vehicle_id=target_vehicle_id,
            target_server_password=target_server_password,
            target_vehicle_name=target_vehicle_name,
            target_module_password=target_module_password,
            is_active=is_active
        )
    except ValidationError as e:
        error_detail = f"{e.errors()['loc'].capitalize()}: {e.errors()['msg']}"
        return RedirectResponse(url=f"{redirect_url_on_error}?error_message={quote_plus(str(error_detail))}", status_code=status.HTTP_303_SEE_OTHER)
        
    crud.autoprovision.update_auto_provision_profile(db, profile_db, profile_in)
    return RedirectResponse(url=f"{request.url_for('ui_manage_autoprovision_profiles')}?success_message={quote_plus(_("Profile '%(key)s' updated successfully.") % {'key': ap_key})}", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/{profile_id}/delete", response_class=RedirectResponse, name="ui_delete_autoprovision_profile")
def ui_delete_autoprovision_profile_route(
    request: Request, profile_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_user_from_cookie)
):
    _ = get_translator(request)
    redirect_url = str(request.url_for('ui_manage_autoprovision_profiles'))

    # Verify CSRF token
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    profile_to_delete = crud.autoprovision.get_auto_provision_profile_by_id(db, profile_id)

    if not profile_to_delete:
        return RedirectResponse(url=f"{redirect_url}?error_message={quote_plus(_("Profile not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    
    deleted_key = profile_to_delete.ap_key
    crud.autoprovision.delete_auto_provision_profile(db, profile_id)
        
    return RedirectResponse(url=f"{redirect_url}?success_message={quote_plus(_("Profile '%(key)s' deleted successfully.") % {'key': deleted_key})}", status_code=status.HTTP_303_SEE_OTHER)