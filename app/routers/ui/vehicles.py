from urllib.parse import quote_plus
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any, Iterator
import asyncio
import json
import csv
import io
import datetime
from uuid import UUID
from fastapi.concurrency import run_in_threadpool
import re
import secrets
from pydantic import ValidationError

from app.database import get_db
from app.connection_manager import manager
from app import crud
from app.models import api as models_api
from app.models import db as models_db
from app.utils.crypto import decrypt_data
from app.utils.csv_safety import sanitize_csv_cell, sanitize_csv_row
from app.utils.email_validation import InvalidEmailAddress, validate_email_address
from . import templates, get_common_template_vars, get_translator
from app.dependencies import require_current_user_from_cookie_fully_authenticated
from app.services.vehicle_service import (
    KartoDeletionFailed,
    send_command_to_vehicle,
    trigger_karto_vehicle_deletion,
)
from app.utils.vehicle_data_presenter import parse_crash_log_data, parse_stored_msgs_for_vehicle_info
from app.utils.datalog_definitions import DATALOG_DEFINITIONS
from zoneinfo import ZoneInfo
from app.utils.vehicle_state_parser import parse_v2_messages_to_metrics_dict
from app.utils.timestamps import as_utc
from app.metrics_manager import metrics_manager
from app.csrf_protection import verify_csrf_token, get_csrf_token
import logging

logger = logging.getLogger(__name__)
router = APIRouter() 

def _dashboard_url(request: Request, user: models_db.User) -> str:
    """Landing page to return to after a vehicle action.

    Admins have no user dashboard: sending them there bounces them to the admin
    dashboard with 'Admins do not have a vehicle dashboard.' and swallows the
    success message for the action they just performed.
    """
    return str(request.url_for('ui_admin_dashboard' if user.is_admin else 'ui_dashboard'))


def _parse_crash_logs_sync(logs_from_db: List[models_db.HistoricalData]) -> List[Dict[str, Any]]:
    """Synchronous helper to parse a list of crash logs."""
    return [
        {"timestamp": log.timestamp, "record_type": log.record_type, "parsed": parse_crash_log_data(log.data_payload)}
        for log in logs_from_db
    ]


def _create_user_friendly_v3_metric_groups(metrics: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Groups a flat dictionary of V3 metrics into user-friendly categories.
    """
    if not metrics:
        return {}

    group_definitions = [
        ("Battery Cells", "v.b.p."),
        ("Battery Cells", "v.b.c."),
        ("12V System", "v.e.12v"),
        ("12V System", "v.c.12v"),
        ("12V System", "v.b.12v"),
        ("Charging", "v.c."),
        ("Main Battery", "v.b."),
        ("Environment", "v.e."),
        ("Position (GPS)", "v.p."),
        ("Doors & Windows", "v.d."),
        ("Tires", "v.t."),
        ("Service", "v.s."),
        ("Vehicle", "v."),
    ]
    
    grouped: Dict[str, Dict[str, Any]] = {}

    for key, value in sorted(metrics.items()):
        if key.startswith('x'):
            group_name = "Vehicle Specific"
            if group_name not in grouped:
                grouped[group_name] = {}
            grouped[group_name][key] = value
            continue 

        if key.startswith('s.'):
            group_name = "Server / System"
            if group_name not in grouped:
                grouped[group_name] = {}
            grouped[group_name][key] = value
            continue 

        assigned_group = "Miscellaneous"
        for group_name, prefix in group_definitions:
            if key.startswith(prefix):
                assigned_group = group_name
                break
        
        if assigned_group not in grouped:
            grouped[assigned_group] = {}
        
        grouped[assigned_group][key] = value

    return dict(sorted(grouped.items()))


@router.get("/suggest-id", response_class=JSONResponse, name="ui_suggest_vehicle_id")
def ui_suggest_vehicle_id_route(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    prefixes = ['EV', 'CAR', 'VEH', 'MOD']
    # Not `for _`: the routes in this module bind gettext to `_`, and a loop variable
    # of that name shadows it for the rest of the function. Nothing is translated
    # inside this loop, so it was harmless here — but the next edit that adds a
    # `_("...")` would have failed confusingly on an int.
    for _attempt in range(20):
        prefix = secrets.choice(prefixes)
        num = secrets.randbelow(9000) + 1000
        candidate = f"{prefix}{num}"
        if not crud.vehicle.get_vehicle_by_vehicle_id(db, candidate):
            return JSONResponse({"vehicle_id": candidate})
    return JSONResponse({"vehicle_id": "VEH" + secrets.token_hex(3).upper()})


@router.get("/add", response_class=HTMLResponse, name="ui_add_vehicle_form")
def ui_add_vehicle_form_route(
    request: Request,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    common_vars = get_common_template_vars(request, current_user)
    
    all_users = []
    if current_user.is_admin:
        all_users = list(crud.user.get_non_admin_users(db))

    return templates.TemplateResponse(request, "add_vehicle_wizard.html", {
        **common_vars,
        "all_users": all_users,
        "form_action_url": request.url_for('ui_add_vehicle_submit')
    })

@router.post("/add", response_class=RedirectResponse, name="ui_add_vehicle_submit")
def ui_add_vehicle_submit_route(
    request: Request,
    vehicle_id: str = Form(...),
    vehicle_name: Optional[str] = Form(None),
    server_password: str = Form(...),
    module_password: Optional[str] = Form(None),
    # Matches the wizard's own default. Only reached if the form omits the field
    # entirely, which the wizard never does — but 'both' as the fallback silently
    # enabled V2 TCP authentication for a vehicle whose owner never asked for it.
    protocol: str = Form('v3'),
    notification_preference: Optional[str] = Form('v3'),
    enable_trip_tracking: bool = Form(False),
    enable_charge_logging: bool = Form(False),
    enable_ntfy_notifications: bool = Form(False),
    enable_email_notifications: bool = Form(False),
    enable_push_notifications: bool = Form(False),
    ntfy_topic: Optional[str] = Form(None),
    ntfy_server_url: Optional[str] = Form(None),
    ntfy_auth_method: Optional[str] = Form(None),
    ntfy_auth_token: Optional[str] = Form(None),
    ntfy_auth_user: Optional[str] = Form(None),
    ntfy_auth_password: Optional[str] = Form(None),
    ntfy_auth_query_param_name: Optional[str] = Form(None),
    notification_email: Optional[str] = Form(None),
    fcm_token: Optional[str] = Form(None),
    apns_token: Optional[str] = Form(None),
    unified_push_endpoint: Optional[str] = Form(None),
    paranoid_token: Optional[str] = Form(None),
    owner_id: Optional[int] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    # Verify CSRF token
    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{request.url_for('ui_add_vehicle_form')}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_id_upper = vehicle_id.upper()
    if not re.fullmatch(r"[A-Z0-9-]+", vehicle_id_upper):
        return RedirectResponse(url=f"{request.url_for('ui_add_vehicle_form')}?error_message={quote_plus(_("Vehicle ID must only contain letters, numbers, and hyphens."))}", status_code=status.HTTP_303_SEE_OTHER)
    
    if crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id_upper):
        # The regex above already constrains this to [A-Z0-9-], so nothing here needs
        # escaping today. Escaped anyway so the safety comes from this line rather than
        # from a check five lines up that a later edit could move or loosen.
        msg = quote_plus(f"Vehicle ID '{vehicle_id_upper}' already exists.")
        return RedirectResponse(url=f"{request.url_for('ui_add_vehicle_form')}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)

    owner_id_to_use = current_user.id
    if current_user.is_admin:
        add_form_url = str(request.url_for('ui_add_vehicle_form'))
        if owner_id is None:
            return RedirectResponse(url=f"{add_form_url}?error_message={quote_plus(_("Admin must select an owner for the vehicle."))}", status_code=status.HTTP_303_SEE_OTHER)
        
        owner_user = crud.user.get_user_by_id(db, user_id=owner_id)
        if not owner_user:
            return RedirectResponse(url=f"{add_form_url}?error_message={quote_plus(_("Selected owner not found."))}", status_code=status.HTTP_303_SEE_OTHER)
        if owner_user.is_admin:
            return RedirectResponse(url=f"{add_form_url}?error_message={quote_plus(_("Cannot assign a vehicle to an administrator."))}", status_code=status.HTTP_303_SEE_OTHER)
        
        owner_id_to_use = owner_user.id

    try:
        vehicle_in = models_api.VehicleCreate(
            vehicle_id=vehicle_id_upper, vehicle_name=vehicle_name, server_password=server_password,
            module_password=module_password, owner_id=owner_id_to_use, protocol=protocol,
            notification_preference=notification_preference, enable_trip_tracking=enable_trip_tracking,
            enable_charge_logging=enable_charge_logging,
            enable_ntfy_notifications=enable_ntfy_notifications, enable_email_notifications=enable_email_notifications,
            enable_fcm_notifications=enable_push_notifications, enable_apns_notifications=enable_push_notifications,
            ntfy_topic=ntfy_topic or None, ntfy_server_url=ntfy_server_url or None,
            ntfy_auth_method=ntfy_auth_method if ntfy_auth_method and ntfy_auth_method != "" else None,
            ntfy_auth_token=ntfy_auth_token or None, ntfy_auth_user=ntfy_auth_user or None,
            ntfy_auth_password=ntfy_auth_password or None, ntfy_auth_query_param_name=ntfy_auth_query_param_name or None,
            notification_email=notification_email or None, fcm_token=fcm_token or None,
            apns_token=apns_token or None, unified_push_endpoint=unified_push_endpoint or None,
            paranoid_token=paranoid_token
        )
    except ValidationError as e:
        # Extract user-friendly error messages
        error_messages = []
        for error in e.errors():
            field = error.get('loc', [''])[0]
            msg = error.get('msg', _('Invalid value'))
            if field == 'server_password':
                if 'too_long' in error.get('type', ''):
                    error_messages.append(_("Server password is too long (max 64 characters)"))
                elif 'too_short' in error.get('type', ''):
                    error_messages.append(_("Server password is required"))
                else:
                    error_messages.append(f"{_('Server password')}: {msg}")
            else:
                error_messages.append(f"{field}: {msg}")

        error_message = "; ".join(error_messages)
        logger.error(f"Validation error adding vehicle: {error_message}")
        return RedirectResponse(url=f"{request.url_for('ui_add_vehicle_form')}?error_message={quote_plus(str(error_message))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.vehicle.create_vehicle(db, vehicle_in, owner_id=owner_id_to_use)
    return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?success_message={quote_plus(_("Vehicle '%(id)s' added successfully.") % {'id': vehicle_id_upper})}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/{vehicle_db_id}/edit", response_class=HTMLResponse, name="ui_edit_vehicle_form")
def ui_edit_vehicle_form_route(
    request: Request, vehicle_db_id: int, db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    common_vars = get_common_template_vars(request, current_user)
    db_vehicle = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not db_vehicle:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    if not current_user.is_admin and db_vehicle.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized to edit this vehicle."))}", status_code=status.HTTP_303_SEE_OTHER)
    
    vehicle_api_model = models_api.VehicleSecureInfo.model_validate(db_vehicle, from_attributes=True)
    if db_vehicle.owner:
        vehicle_api_model.owner_username = db_vehicle.owner.username

    paranoid_token_display = ""
    if db_vehicle.paranoid_token:
        try:
            paranoid_token_display = decrypt_data(db_vehicle.paranoid_token)
        except Exception:
            paranoid_token_display = ""

    return templates.TemplateResponse(request, "edit_vehicle.html", {
        **common_vars,
        "vehicle": vehicle_api_model,
        "paranoid_token_display": paranoid_token_display,
        "page_title": f"Edit Vehicle: {db_vehicle.vehicle_id}",
        "form_action_url": request.url_for('ui_edit_vehicle_submit', vehicle_db_id=vehicle_db_id)
    })

@router.post("/{vehicle_db_id}/edit", response_class=RedirectResponse, name="ui_edit_vehicle_submit")
def ui_edit_vehicle_submit_route(
    request: Request, vehicle_db_id: int,
    vehicle_id: str = Form(...), vehicle_name: Optional[str] = Form(None),
    server_password: Optional[str] = Form(None), module_password: Optional[str] = Form(None),
    protocol: str = Form('both'), notification_preference: Optional[str] = Form('v3'),
    enable_trip_tracking: bool = Form(False),
    enable_charge_logging: bool = Form(False),
    paranoid_token: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    # Verify CSRF token
    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    current_db_vehicle = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not current_db_vehicle:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle to update not found."))}", status_code=status.HTTP_303_SEE_OTHER)

    if not current_user.is_admin and current_db_vehicle.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized to edit this vehicle."))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_id_upper = vehicle_id.upper()
    if not re.fullmatch(r"[A-Z0-9-]+", vehicle_id_upper):
        return RedirectResponse(url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}?error_message={quote_plus(_("Vehicle ID must only contain letters, numbers, and hyphens."))}", status_code=status.HTTP_303_SEE_OTHER)
    if vehicle_id_upper != current_db_vehicle.vehicle_id:
        return RedirectResponse(url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}?error_message={quote_plus(_("Vehicle ID cannot be changed after creation."))}", status_code=status.HTTP_303_SEE_OTHER)

    # An empty field means "no display name" — store NULL instead of an empty string
    vehicle_name = vehicle_name.strip() if vehicle_name else None
    if not vehicle_name:
        vehicle_name = None

    update_payload = {
        "vehicle_id": vehicle_id_upper, "vehicle_name": vehicle_name, "module_password": module_password,
        "protocol": protocol, "notification_preference": notification_preference,
        "enable_trip_tracking": enable_trip_tracking,
        "enable_charge_logging": enable_charge_logging,
    }
    if server_password: update_payload["server_password"] = server_password

    try:
        vehicle_update = models_api.VehicleUpdate(**update_payload)
    except ValidationError as e:
        # Extract user-friendly error messages
        error_messages = []
        for error in e.errors():
            field = error.get('loc', [''])[0]
            msg = error.get('msg', _('Invalid value'))
            if field == 'server_password':
                if 'too_long' in error.get('type', ''):
                    error_messages.append(_("Server password is too long (max 64 characters)"))
                elif 'too_short' in error.get('type', ''):
                    error_messages.append(_("Server password cannot be empty"))
                else:
                    error_messages.append(f"{_('Server password')}: {msg}")
            else:
                error_messages.append(f"{field}: {msg}")

        error_message = "; ".join(error_messages)
        logger.error(f"Validation error updating vehicle: {error_message}")
        return RedirectResponse(url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}?error_message={quote_plus(str(error_message))}", status_code=status.HTTP_303_SEE_OTHER)

    updated = crud.vehicle.update_vehicle(db, vehicle_db_id, vehicle_update)
    if not updated:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found for update (unexpected)."))}", status_code=status.HTTP_303_SEE_OTHER)

    db.commit()

    return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?success_message={quote_plus(_("Vehicle '%(id)s' updated successfully.") % {'id': updated.vehicle_id})}", status_code=status.HTTP_303_SEE_OTHER)

@router.post("/{vehicle_db_id}/delete", response_class=RedirectResponse, name="ui_delete_vehicle")
async def ui_delete_vehicle_route(
    request: Request, vehicle_db_id: int,
    delete_confirmation: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    # Verify CSRF token
    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_to_delete = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not vehicle_to_delete:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found for deletion."))}", status_code=status.HTTP_303_SEE_OTHER)

    if not current_user.is_admin and vehicle_to_delete.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized to delete this vehicle."))}", status_code=status.HTTP_303_SEE_OTHER)

    if delete_confirmation != vehicle_to_delete.vehicle_id:
        return RedirectResponse(url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}?error_message={quote_plus(_("Incorrect confirmation text. Vehicle deletion cancelled."))}", status_code=status.HTTP_303_SEE_OTHER)

    # Karto first, and only proceed if it confirmed. Deleting the vehicle while its
    # GPS history survives would leave that history orphaned — and the vehicle id is
    # free again afterwards, so the next registration would inherit it.
    try:
        await trigger_karto_vehicle_deletion(db, vehicle_to_delete.vehicle_id, current_user)
    except KartoDeletionFailed as e:
        logger.error(f"Aborting deletion of vehicle {vehicle_to_delete.vehicle_id}: {e}")
        return RedirectResponse(
            url=f"{request.url_for('ui_edit_vehicle_form', vehicle_db_id=vehicle_db_id)}"
                f"?error_message={quote_plus(_("Trip data could not be deleted right now, so the vehicle was kept. Please try again shortly."))}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    car_conn = manager.get_car_connection(vehicle_to_delete.vehicle_id)
    if car_conn: await car_conn.close() 

    crud.vehicle.delete_vehicle(db, vehicle_db_id)
    return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?success_message={quote_plus(_("Vehicle '%(id)s' deleted successfully.") % {'id': vehicle_to_delete.vehicle_id})}", status_code=status.HTTP_303_SEE_OTHER)

@router.get("/{vehicle_module_id}", response_class=HTMLResponse, name="ui_vehicle_detail_page")
async def ui_vehicle_detail_page_route(
    request: Request, vehicle_module_id: str, db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    if current_user.is_admin:
        return RedirectResponse(url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(_("Admins cannot view detailed vehicle information."))}", status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    vehicle_id_upper = vehicle_module_id.upper()
    db_vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id_upper)
    
    if not db_vehicle:
        # Unlike the add route, this value is a *path* parameter and passes no regex —
        # a request for /vehicles/A%26tab%3Dx reaches here verbatim, so an unescaped
        # interpolation would let the caller append query parameters of their own.
        msg = quote_plus(f"Vehicle '{vehicle_id_upper}' not found.")
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={msg}", status_code=status.HTTP_303_SEE_OTHER)
    if not current_user.is_admin and db_vehicle.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized to view this vehicle's details."))}", status_code=status.HTTP_303_SEE_OTHER)

    crash_logs_db = crud.historical_data.get_historical_data_for_vehicle(db, vehicle_id_upper, record_type_like="%Crash%", limit=50)
    debug_logs_db = crud.historical_data.get_historical_data_for_vehicle(
        db, vehicle_id_upper, record_type_like="%Debug%", exclude_record_type_like="%Crash%", limit=50
    )
    # Vehicle history records (data notifications, e.g. *-LOG-Trip / *-LOG-Grid), grouped
    # by record type. Crash/debug records have their own cards above.
    datalog_summary = [
        s for s in crud.historical_data.get_historical_summary(db, vehicle_id_upper)
        if 'crash' not in s['h_recordtype'].lower() and 'debug' not in s['h_recordtype'].lower()
    ]
    v2_metrics_flat = await run_in_threadpool(parse_v2_messages_to_metrics_dict, db_vehicle)
    v3_metrics_flat = metrics_manager.get_metrics_for_vehicle(vehicle_id_upper)

    # Filter out V2-sourced charge logging metrics from V3 display if vehicle is V2-only
    # These metrics are stored in metrics_manager by V2 protocol handlers for charge logging
    # but should not appear as "V3/MQTT metrics" when the vehicle doesn't actually use V3
    if v3_metrics_flat and db_vehicle.protocol == 'v2':
        v2_charge_metrics = {
            'v.c.charging', 'v.b.soc', 'v.c.power', 'v.c.kwh', 'v.b.temp',
            'v.o.odometer', 'v.p.latitude', 'v.p.longitude'
        }
        v3_metrics_flat = {k: v for k, v in v3_metrics_flat.items() if k not in v2_charge_metrics}

    v2_metrics_grouped = {}
    for key, value in v2_metrics_flat.items():
        prefix, _, rest = key.partition('.')
        if prefix not in v2_metrics_grouped: v2_metrics_grouped[prefix] = {}
        v2_metrics_grouped[prefix][rest] = value

    v3_metrics_grouped = _create_user_friendly_v3_metric_groups(v3_metrics_flat)

    (parsed_info, parsed_crash_logs) = await asyncio.gather(
        run_in_threadpool(parse_stored_msgs_for_vehicle_info, db_vehicle),
        run_in_threadpool(_parse_crash_logs_sync, crash_logs_db)
    )
    status_parsed, loc_parsed, tpms_parsed, diag_parsed = parsed_info

    debug_logs = [
        {"timestamp": log.timestamp, "record_type": log.record_type, "data": log.data_payload}
        for log in debug_logs_db
    ]

    is_v2_online = db_vehicle.vehicle_id in manager.car_connections
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    is_v3_online = False
    if db_vehicle.last_seen_v3 and (now_utc - db_vehicle.last_seen_v3.replace(tzinfo=datetime.timezone.utc)).total_seconds() < (15 * 60):
        is_v3_online = True

    vehicle_info = models_api.VehicleInfo.from_orm(db_vehicle)
    if db_vehicle.owner: vehicle_info.owner_username = db_vehicle.owner.username
    
    initial_live_data = {
        'isV2Online': is_v2_online, 'isV3Online': is_v3_online,
        'soc': status_parsed.get('soc') if status_parsed else None, 'units': status_parsed.get('units') if status_parsed else None,
        'line_voltage': status_parsed.get('line_voltage') if status_parsed else None, 'charge_current': status_parsed.get('charge_current') if status_parsed else None,
        'charge_state_text': status_parsed.get('charge_state_text') if status_parsed else None, 'charge_mode_text': status_parsed.get('charge_mode_text') if status_parsed else None,
        'estimated_range': status_parsed.get('estimated_range') if status_parsed else None, 'battery_voltage': status_parsed.get('battery_voltage') if status_parsed else None,
        'battery_current': status_parsed.get('battery_current') if status_parsed else None, 'battery_soh': status_parsed.get('battery_soh') if status_parsed else None,
        'vehicle_12v': diag_parsed.get('vehicle_12v') if diag_parsed else None, 'lat': loc_parsed.get('lat') if loc_parsed else None,
        'lon': loc_parsed.get('lon') if loc_parsed else None,
        'lastMessageAt': db_vehicle.last_message_at.isoformat() + "Z" if db_vehicle.last_message_at else None,
        'tpms_data': tpms_parsed if tpms_parsed else None,
        'v3_metrics': v3_metrics_flat,
    }
            
    push_subscriptions = crud.push_subscription.get_subscriptions_for_vehicle(db, db_vehicle.id)

    return templates.TemplateResponse(request, "vehicle_detail.html", {
        **common_vars, "vehicle": vehicle_info, "is_v2_online": is_v2_online, "is_v3_online": is_v3_online,
        "crash_logs": parsed_crash_logs, "debug_logs": debug_logs, "v2_metrics_grouped": v2_metrics_grouped, "v3_metrics_grouped": v3_metrics_grouped,
        # Passed as a dict, not a pre-serialized string, so the template can render it
        # with |tojson. That filter is overridden in app/routers/ui/__init__.py and is
        # the single place where the <, > and & escaping happens — without it the
        # car-supplied values here (units, v3_metrics) break out of the <script> block.
        # Matches the sibling metric groups above.
        "initial_live_data": initial_live_data, "page_title": f"Vehicle Detail: {vehicle_id_upper}",
        "push_subscriptions": push_subscriptions, "datalog_summary": datalog_summary,
    })

@router.get("/{vehicle_module_id}/trip/{trip_id}", response_class=HTMLResponse, name="ui_vehicle_trip_detail_page")
def ui_vehicle_trip_detail_page_route(
    request: Request, vehicle_module_id: str, trip_id: UUID,
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    db: Session = Depends(get_db)
):
    _ = get_translator(request)
    if current_user.is_admin:
        return RedirectResponse(url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(_("Admins cannot view trip information."))}", status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    vehicle_id = vehicle_module_id.upper()
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
    if not vehicle_db or (not current_user.is_admin and vehicle_db.owner_id != current_user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found or not authorized.")
        
    # This route now only serves the container page.
    # The actual data fetching happens client-side via Alpine.js.
    return templates.TemplateResponse(request, "trip_detail.html", {
        **common_vars,
        "vehicle": vehicle_db,
        "trip_id": trip_id,
        "page_title": f"Trip Detail for {vehicle_id}"
    })

@router.get("/{vehicle_module_id}/charge/{charge_log_id}", response_class=HTMLResponse, name="ui_vehicle_charge_detail_page")
def ui_vehicle_charge_detail_page_route(
    request: Request, vehicle_module_id: str, charge_log_id: UUID,
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
    db: Session = Depends(get_db)
):
    _ = get_translator(request)
    if current_user.is_admin:
        return RedirectResponse(url=f"{request.url_for('ui_admin_dashboard')}?error_message={quote_plus(_("Admins cannot view charge information."))}", status_code=status.HTTP_303_SEE_OTHER)

    common_vars = get_common_template_vars(request, current_user)
    vehicle_id = vehicle_module_id.upper()
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
    if not vehicle_db or (not current_user.is_admin and vehicle_db.owner_id != current_user.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found or not authorized.")

    return templates.TemplateResponse(request, "charge_detail.html", {
        **common_vars,
        "vehicle": vehicle_db,
        "charge_log_id": charge_log_id,
        "page_title": f"Charge Detail for {vehicle_id}"
    })

@router.post("/{vehicle_module_id}/push/add-ntfy", response_class=RedirectResponse, name="ui_add_ntfy_subscription")
def ui_add_ntfy_subscription_route(
    request: Request, vehicle_module_id: str,
    ntfy_topic: str = Form(...),
    ntfy_server_url: Optional[str] = Form(None),
    ntfy_auth_method: Optional[str] = Form(None),
    ntfy_auth_token: Optional[str] = Form(None),
    ntfy_auth_user: Optional[str] = Form(None),
    ntfy_auth_password: Optional[str] = Form(None),
    ntfy_auth_query_param_name: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    detail_url = request.url_for('ui_vehicle_detail_page', vehicle_module_id=vehicle_module_id.upper())
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{detail_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized."))}", status_code=status.HTTP_303_SEE_OTHER)

    topic = ntfy_topic.strip()
    if not topic:
        return RedirectResponse(url=f"{detail_url}?error_message={quote_plus(_("ntfy topic cannot be empty."))}", status_code=status.HTTP_303_SEE_OTHER)

    if ntfy_server_url:
        try:
            models_api._validate_ntfy_server_url(ntfy_server_url)
        except ValueError as e:
            return RedirectResponse(url=f"{detail_url}?error_message={quote_plus(str(e))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.push_subscription.add_manual_ntfy(
        db, vehicle_db.id,
        topic=topic,
        server_url=ntfy_server_url or None,
        auth_method=ntfy_auth_method if ntfy_auth_method and ntfy_auth_method != "none" else None,
        auth_token=ntfy_auth_token or None,
        auth_user=ntfy_auth_user or None,
        auth_password=ntfy_auth_password or None,
        auth_query_param_name=ntfy_auth_query_param_name or None,
    )
    db.commit()
    return RedirectResponse(url=f"{detail_url}?success_message={quote_plus(_("ntfy topic added."))}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{vehicle_module_id}/push/add-email", response_class=RedirectResponse, name="ui_add_email_recipient")
def ui_add_email_recipient_route(
    request: Request, vehicle_module_id: str,
    notification_email: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    detail_url = request.url_for('ui_vehicle_detail_page', vehicle_module_id=vehicle_module_id.upper())
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{detail_url}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized."))}", status_code=status.HTTP_303_SEE_OTHER)

    # A bare '@' check let CR/LF through, which the SMTP layer would have turned
    # into attacker-chosen extra headers.
    try:
        email = validate_email_address(notification_email)
    except InvalidEmailAddress:
        return RedirectResponse(url=f"{detail_url}?error_message={quote_plus(_("Invalid email address."))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.push_subscription.add_manual_email(db, vehicle_db.id, email)
    db.commit()
    return RedirectResponse(url=f"{detail_url}?success_message={quote_plus(_("Email recipient added."))}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{vehicle_module_id}/push/{subscription_id}/delete", response_class=RedirectResponse, name="ui_delete_push_subscription")
def ui_delete_push_subscription_route(
    request: Request, vehicle_module_id: str, subscription_id: int,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    _ = get_translator(request)
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException as e:
        return RedirectResponse(url=f"{request.url_for('ui_vehicle_detail_page', vehicle_module_id=vehicle_module_id)}?error_message={quote_plus(_(str(e.detail)))}", status_code=status.HTTP_303_SEE_OTHER)

    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Vehicle not found."))}", status_code=status.HTTP_303_SEE_OTHER)
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        return RedirectResponse(url=f"{_dashboard_url(request, current_user)}?error_message={quote_plus(_("Not authorized."))}", status_code=status.HTTP_303_SEE_OTHER)

    crud.push_subscription.delete_subscription(db, subscription_id, vehicle_db.id)
    return RedirectResponse(url=f"{request.url_for('ui_vehicle_detail_page', vehicle_module_id=vehicle_module_id.upper())}?success_message={quote_plus(_("Push subscription removed."))}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/{vehicle_module_id}/command-ajax", name="ui_send_command_to_vehicle_ajax")
async def ui_send_command_to_vehicle_ajax_route(
    request: Request, vehicle_module_id: str,
    command_str: str = Form(...),
    protocol_preference: Optional[str] = Form(None),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token validation failed")

    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found.")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to command this vehicle.")

    result = await send_command_to_vehicle(vehicle_db, command_str, protocol_preference)
    result_data = result.model_dump()
    result_data["csrf_token"] = get_csrf_token(request)
    return JSONResponse(content=result_data)

@router.get("/{vehicle_db_id}/crashlogs/download", name="ui_download_crash_logs")
def download_crash_logs_csv_route(
    vehicle_db_id: int, db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    db_vehicle = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not db_vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found.")
    if not current_user.is_admin and db_vehicle.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this vehicle's logs.")
    
    crash_logs = crud.historical_data.get_historical_data_for_vehicle(db, db_vehicle.vehicle_id, record_type_like="%Crash%", limit=1000) 

    def iter_csv() -> Iterator[str]:
        output = io.StringIO()
        writer = csv.writer(output)
        header = ['timestamp_utc', 'firmware', 'build_id', 'reason_code', 'reason_text', 'is_abort', 'pc', 'exc_cause', 'is_our_abort', 'abort_details', 'crash_task_prio', 'crash_task_name', 'running_task_prio', 'running_task_name', 'running_task_state', 'last_event_prio', 'last_event_sender', 'last_event_prio_prev', 'last_event_sender_prev', 'running_task_runtime', 'last_event_subscriber', 'last_event_subscriber_prev', 'backtrace']
        writer.writerow(header)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        for log in crash_logs:
            parsed = parse_crash_log_data(log.data_payload)
            row = [log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else ""] + [parsed.get(h, "") for h in header[1:]]
            row = sanitize_csv_row(row)
            writer.writerow(row)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    filename = f"crashlogs_{db_vehicle.vehicle_id}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(iter_csv(), media_type="text/csv", headers={'Content-Disposition': f'attachment; filename="{filename}"'})


_DATALOG_PAGE_SIZE = 100

def _get_datalog_vehicle_or_raise(db: Session, current_user: models_db.User, vehicle_module_id: str) -> models_db.Vehicle:
    db_vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not db_vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found.")
    if not current_user.is_admin and db_vehicle.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this vehicle's data logs.")
    return db_vehicle

@router.get("/{vehicle_module_id}/datalogs", response_class=HTMLResponse, name="ui_vehicle_datalogs_page")
def ui_vehicle_datalogs_page_route(
    request: Request, vehicle_module_id: str,
    type: Optional[str] = None, page: int = 1,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """History records (data notifications) of a vehicle: type overview plus a paged,
    column-split view of the records of one type."""
    db_vehicle = _get_datalog_vehicle_or_raise(db, current_user, vehicle_module_id)
    common_vars = get_common_template_vars(request, current_user)
    vehicle_id = db_vehicle.vehicle_id

    summary = [
        s for s in crud.historical_data.get_historical_summary(db, vehicle_id)
        if 'crash' not in s['h_recordtype'].lower() and 'debug' not in s['h_recordtype'].lower()
    ]

    page = max(1, page)
    records = []
    max_fields = 0
    has_more = False
    if type:
        records_db = crud.historical_data.get_historical_data_for_vehicle(
            db, vehicle_id, record_type_equals=type,
            skip=(page - 1) * _DATALOG_PAGE_SIZE, limit=_DATALOG_PAGE_SIZE + 1
        )
        has_more = len(records_db) > _DATALOG_PAGE_SIZE
        for log in records_db[:_DATALOG_PAGE_SIZE]:
            fields = log.data_payload.split(',') if log.data_payload else []
            max_fields = max(max_fields, len(fields))
            records.append({"timestamp": log.timestamp, "record_number": log.record_number, "fields": fields})

    # Known record types get named columns and trend charts (one measure per chart)
    definition = DATALOG_DEFINITIONS.get(type) if type else None
    field_names = definition["fields"] if definition else []
    headers = [field_names[i] if i < len(field_names) else f"F{i + 1}" for i in range(max_fields)]

    charts = []
    if definition and definition.get("charts") and records:
        try:
            tz = ZoneInfo(common_vars.get("user_timezone") or "UTC")
        except Exception:
            tz = datetime.timezone.utc
        chart_records = crud.historical_data.get_historical_data_for_vehicle(
            db, vehicle_id, record_type_equals=type, limit=1000, sort_ascending=True
        )
        # as_utc() first: a naive value is a stored UTC timestamp with its label
        # missing (SQLite has no timezone type), and astimezone() on a naive datetime
        # reads it as *system local time* instead. On a server not running in UTC that
        # shifted every chart label by the offset — on SQLite only, which is why the
        # same page was correct on PostgreSQL. The Jinja filter in ui/__init__.py
        # normalises for exactly this reason; this call site did not.
        labels = [as_utc(r.timestamp).astimezone(tz).strftime('%Y-%m-%d %H:%M') if r.timestamp else '' for r in chart_records]
        for chart_def in definition["charts"]:
            data = []
            for r in chart_records:
                fields = r.data_payload.split(',') if r.data_payload else []
                try:
                    data.append(float(fields[chart_def["index"]]))
                except (IndexError, ValueError):
                    data.append(None)
            if sum(1 for v in data if v is not None) >= 2:
                charts.append({"title": chart_def["title"], "label": chart_def["label"],
                               "color": chart_def["color"], "labels": labels, "data": data})

    return templates.TemplateResponse(request, "vehicle_datalogs.html", {
        **common_vars, "vehicle": db_vehicle, "summary": summary,
        "selected_type": type, "records": records, "headers": headers,
        "description": definition["description"] if definition else None,
        "charts": charts, "charts_json": json.dumps(charts) if charts else None,
        "page": page, "has_more": has_more,
        "page_title": f"Data Logs: {vehicle_id}",
    })

@router.get("/{vehicle_module_id}/datalogs/export", name="ui_vehicle_datalogs_export")
def ui_vehicle_datalogs_export_route(
    vehicle_module_id: str, type: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """CSV export of all stored records of one record type."""
    db_vehicle = _get_datalog_vehicle_or_raise(db, current_user, vehicle_module_id)

    records_db = crud.historical_data.get_historical_data_for_vehicle(
        db, db_vehicle.vehicle_id, record_type_equals=type, limit=10000, sort_ascending=True
    )

    definition = DATALOG_DEFINITIONS.get(type)
    field_names = definition["fields"] if definition else []
    max_fields = max((len(log.data_payload.split(',')) for log in records_db if log.data_payload), default=0)
    header = ['timestamp_utc', 'record_number'] + [
        field_names[i] if i < len(field_names) else f"F{i + 1}" for i in range(max_fields)
    ]

    def iter_csv() -> Iterator[str]:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(header)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)
        for log in records_db:
            fields = log.data_payload.split(',') if log.data_payload else []
            row = [log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "", log.record_number]
            row += [sanitize_csv_cell(f) for f in fields]
            writer.writerow(row)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    safe_type = re.sub(r'[^A-Za-z0-9_.-]+', '_', type)
    filename = f"datalog_{db_vehicle.vehicle_id}_{safe_type}_{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(iter_csv(), media_type="text/csv", headers={'Content-Disposition': f'attachment; filename="{filename}"'})
