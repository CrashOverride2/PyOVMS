from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, status as http_status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
import base64
import logging
from fastapi.concurrency import run_in_threadpool

from app import crud, notifications
from app.models import api as models_api, db as models_db
from app.database import get_db
from app.connection_manager import manager as v2_manager
from app.services.vehicle_service import (
    KartoDeletionFailed,
    send_command_to_vehicle,
    trigger_karto_vehicle_deletion,
)
from app.utils.datalog_definitions import DATALOG_DEFINITIONS
from app.utils.email_validation import MAX_EMAIL_LENGTH, validate_email_address
from app.utils.vehicle_data_presenter import parse_crash_log_data
from app.utils.vehicle_state_parser import parse_vehicle_state_to_json, parse_v2_messages_to_metrics_dict
from app.metrics_manager import metrics_manager
from app.dependencies import require_active_api_user, require_admin_api_user
from app.widget_push_service import widget_push_service

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1", 
    tags=["Vehicles & Commands API"],
)

from .users import router as users_router, me_router as users_me_router
from .apikeys import router as apikeys_router
from .websockets import router as websockets_router
from .security_events import router as security_events_router
from .device_auth import router as device_auth_router
from .config_backups import router as config_backups_router

router.include_router(users_router)
router.include_router(users_me_router)
router.include_router(apikeys_router)
router.include_router(websockets_router)
# Unauthenticated by design: this is where a device exchanges credentials for a key.
router.include_router(device_auth_router)
router.include_router(security_events_router, prefix="/security", tags=["Security Events API"])
router.include_router(config_backups_router)


@router.get("/auth/ping", status_code=200, dependencies=[Depends(require_active_api_user)])
def api_auth_ping():
    return {"ok": True}


@router.get("/admin/notifications/queue", status_code=200,
            dependencies=[Depends(require_admin_api_user)],
            tags=["Admin"])
def api_notification_queue_stats():
    """Counters for every queue a notification passes through.

    `mail` — the queue refuses NORMAL and LOW priority mail once it is above
    `normal_priority_limit` so that a password reset still gets through, and it drops a
    message that has exhausted its retries. Both are logged and otherwise invisible;
    `rejected` and `failed` are how an operator sees that it is happening at all.

    `mqtt.dispatch` / `mqtt.data` — the two bounded stages behind the MQTT network
    thread. This is the first place to look when notifications arrive late: a `queued`
    that stays high names the stage that is behind, and `dropped` says it has already
    started shedding. They are separate pools precisely so that a flood of history
    records cannot be mistaken for, or cause, a push backlog.

    `push_retries.pending` — sends that failed transiently and are waiting on a timer.
    A large number here means a push provider is unhealthy, not that this server is.
    """
    from app.mqtt_notification_subscriber import mqtt_notification_subscriber
    from app.notifications.dispatcher import _retry_scheduler
    from app.notifications.email_queue import mail_queue

    return {
        "mail": mail_queue.stats(),
        "mqtt": mqtt_notification_subscriber.stats(),
        "push_retries": _retry_scheduler.stats(),
    }


@router.post("/vehicles", response_model=models_api.VehicleInfo, status_code=http_status.HTTP_201_CREATED,
             dependencies=[Depends(require_active_api_user)])
def api_create_vehicle(
    vehicle_in: models_api.VehicleCreate,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    if crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_in.vehicle_id):
        raise HTTPException(status_code=400, detail=f"Vehicle ID '{vehicle_in.vehicle_id}' already registered.")

    owner_id_to_use = current_user.id
    if current_user.is_admin and vehicle_in.owner_id is not None:
        if not crud.user.get_user_by_id(db, vehicle_in.owner_id):
            raise HTTPException(status_code=404, detail=f"Specified owner ID {vehicle_in.owner_id} not found.")
        owner_id_to_use = vehicle_in.owner_id
    elif not current_user.is_admin and vehicle_in.owner_id is not None and vehicle_in.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to assign vehicle to another user.")

    created_vehicle = crud.vehicle.create_vehicle(db, vehicle_in, owner_id=owner_id_to_use)
    db_vehicle = crud.vehicle.get_vehicle_by_id(db, created_vehicle.id)
    return v2_manager.get_vehicle_info(db, db_vehicle)

@router.get("/vehicles", response_model=List[models_api.VehicleInfo],
            dependencies=[Depends(require_active_api_user)])
def api_list_all_vehicles(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    return v2_manager.get_all_vehicle_infos(db, current_user)

@router.get("/vehicles/{vehicle_db_id}", response_model=models_api.VehicleSecureInfo,
            dependencies=[Depends(require_active_api_user)])
def api_get_vehicle(
    vehicle_db_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    db_vehicle = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not db_vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found by DB ID")

    if not current_user.is_admin and db_vehicle.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this vehicle")

    vehicle_info = v2_manager.get_vehicle_info(db, db_vehicle)
    if not vehicle_info:
        raise HTTPException(status_code=404, detail="Vehicle info could not be composed.")
    return models_api.VehicleSecureInfo.model_validate(vehicle_info)

@router.put("/vehicles/{vehicle_db_id}", response_model=models_api.VehicleInfo,
            dependencies=[Depends(require_active_api_user)])
def api_update_vehicle(
    vehicle_db_id: int,
    vehicle_in: models_api.VehicleUpdate,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    current_vehicle_db = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not current_vehicle_db:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Vehicle to update not found.")

    if not current_user.is_admin and current_vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this vehicle")

    if vehicle_in.vehicle_id is not None and vehicle_in.vehicle_id.upper() != current_vehicle_db.vehicle_id:
        raise HTTPException(status_code=400, detail="Vehicle ID cannot be changed after creation.")

    updated_vehicle = crud.vehicle.update_vehicle(db, vehicle_db_id, vehicle_in)
    if not updated_vehicle:
        raise HTTPException(status_code=404, detail="Vehicle not found by DB ID for update (unexpected).")
    return v2_manager.get_vehicle_info(db, updated_vehicle)

@router.delete("/vehicles/{vehicle_db_id}", status_code=http_status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_active_api_user)])
async def api_delete_vehicle(
    vehicle_db_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    vehicle_to_delete_db = crud.vehicle.get_vehicle_by_id(db, vehicle_db_id)
    if not vehicle_to_delete_db:
        raise HTTPException(status_code=404, detail="Vehicle not found by DB ID for deletion")

    if not current_user.is_admin and vehicle_to_delete_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this vehicle")

    # Karto first, and only proceed if it confirmed — see the UI route for why.
    try:
        await trigger_karto_vehicle_deletion(db, vehicle_to_delete_db.vehicle_id, current_user)
    except KartoDeletionFailed as e:
        logger.error(f"Aborting deletion of vehicle {vehicle_to_delete_db.vehicle_id}: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trip data could not be deleted right now, so the vehicle was kept. Please retry.",
        )

    car_conn = v2_manager.get_car_connection(vehicle_to_delete_db.vehicle_id)
    if car_conn: await car_conn.close() 

    crud.vehicle.delete_vehicle(db, vehicle_db_id) 
    return None

@router.get("/vehicles/{vehicle_module_id}/metrics/available", response_model=models_api.AvailableMetricsResponse,
            dependencies=[Depends(require_active_api_user)])
async def api_get_available_metrics(
    vehicle_module_id: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Get a list of all available V2 (cached) and V3 (live) metric names for a vehicle.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this vehicle's metrics")

    # V2 metrics are derived from cached messages, run in threadpool as it might do some processing
    v2_metrics_dict = await run_in_threadpool(parse_v2_messages_to_metrics_dict, vehicle_db)
    v2_metrics_list = sorted(v2_metrics_dict.keys())

    # V3 metrics are from the in-memory manager, which is fast
    v3_metrics_dict = metrics_manager.get_metrics_for_vehicle(vehicle_db.vehicle_id) or {}
    v3_metrics_list = sorted(v3_metrics_dict.keys())
    
    return models_api.AvailableMetricsResponse(
        vehicle_id=vehicle_db.vehicle_id,
        v2_metrics=v2_metrics_list,
        v3_metrics=v3_metrics_list,
    )

@router.post("/vehicles/{vehicle_module_id}/metrics/query", response_model=models_api.MetricsQueryResponse,
             dependencies=[Depends(require_active_api_user)])
async def api_query_specific_metrics(
    vehicle_module_id: str,
    query_request: models_api.MetricsQueryRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Query the current values for a specific list of metric names.
    The endpoint will check for live V3 metrics first, then fall back to cached V2 metrics.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this vehicle's metrics")

    # Get all available metrics
    v2_metrics_dict = await run_in_threadpool(parse_v2_messages_to_metrics_dict, vehicle_db)
    v3_metrics_dict = metrics_manager.get_metrics_for_vehicle(vehicle_db.vehicle_id) or {}

    response_metrics: Dict[str, Any] = {}

    for metric_name in query_request.metric_names:
        # V3 (live) data takes precedence
        if metric_name in v3_metrics_dict:
            response_metrics[metric_name] = v3_metrics_dict[metric_name]
        # Fallback to V2 (cached) data
        elif metric_name in v2_metrics_dict:
            response_metrics[metric_name] = v2_metrics_dict[metric_name]
        # If not found in either, mark as null
        else:
            response_metrics[metric_name] = None
    
    return models_api.MetricsQueryResponse(
        vehicle_id=vehicle_db.vehicle_id,
        metrics=response_metrics
    )

@router.post("/command/{vehicle_module_id}", response_model=models_api.CommandResponse,
             dependencies=[Depends(require_active_api_user)])
async def send_vehicle_command_api(
    vehicle_module_id: str,
    cmd_req: models_api.CommandRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to command this vehicle")
    
    return await send_command_to_vehicle(vehicle_db, cmd_req.command_code_with_args)

@router.post("/notify/{vehicle_module_id}", status_code=http_status.HTTP_202_ACCEPTED,
             dependencies=[Depends(require_active_api_user)])
def send_manual_notification_api(
    vehicle_module_id: str,
    payload: models_api.ManualNotificationRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to send notifications for this vehicle")

    title_to_use = payload.title or f"PyOVMS Info: {vehicle_db.vehicle_id}"
    background_tasks.add_task(
        notifications.dispatch_notification_to_vehicle,
        vehicle_id=vehicle_db.vehicle_id, title=title_to_use, message_plain=payload.message,
        ntfy_priority=payload.priority or 3, ntfy_tags=payload.tags,
        source_protocol='v2', # Manual notifications are considered v2/UI originated
        alert_type_char='I'
    )
    return {"status": "Notification dispatch accepted", "vehicle_id": vehicle_db.vehicle_id}

@router.post("/autoprovision_profiles", response_model=models_api.AutoProvisionProfileInfo, status_code=http_status.HTTP_201_CREATED,
             dependencies=[Depends(require_admin_api_user)])
def api_create_ap_profile(
    profile_in: models_api.AutoProvisionProfileCreate,
    db: Session = Depends(get_db),
    # Admin-only, matching the UI (ui/autoprovision.py uses require_admin_user_from_cookie).
    # The ownership check below only fires when the target vehicle already exists, so a
    # non-admin could otherwise create a profile for a *not yet registered* vehicle id —
    # pre-seeding server and module passwords of a car someone else is about to add.
    current_user: models_db.User = Depends(require_admin_api_user)
):
    if crud.autoprovision.get_auto_provision_profile(db, profile_in.ap_key):
        raise HTTPException(status_code=400, detail=f"Auto-Provisioning key '{profile_in.ap_key}' already exists.")

    owner_id_to_use = current_user.id
    if current_user.is_admin and profile_in.owner_id is not None:
        if not crud.user.get_user_by_id(db, profile_in.owner_id):
            raise HTTPException(status_code=404, detail=f"Specified owner ID {profile_in.owner_id} not found.")
        owner_id_to_use = profile_in.owner_id
    elif not current_user.is_admin and profile_in.owner_id is not None and profile_in.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to create AP profile for another user.")

    # Non-admins may only target vehicles they own; admins may target any vehicle
    target_vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, profile_in.target_vehicle_id.upper())
    if target_vehicle and not current_user.is_admin and target_vehicle.owner_id != current_user.id:
        raise HTTPException(
            status_code=403,
            detail="Not authorized to create an AP profile targeting a vehicle you do not own."
        )

    if not profile_in.encrypted_module_params_b64:
        dummy_params = f"vehicleid={profile_in.target_vehicle_id.upper()};module.apn=internet.t-mobile"
        profile_in.encrypted_module_params_b64 = base64.b64encode(dummy_params.encode()).decode()

    created_profile = crud.autoprovision.create_auto_provision_profile(db, profile_in, owner_id=owner_id_to_use)
    return models_api.AutoProvisionProfileInfo.from_orm(created_profile)

@router.get("/vehicle_state/{vehicle_module_id}", response_model=Dict[str, Any],
            dependencies=[Depends(require_active_api_user)])
def get_vehicle_state_detailed_api(
    vehicle_module_id: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail=f"Vehicle '{vehicle_module_id.upper()}' not found.")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this vehicle's state")

    return parse_vehicle_state_to_json(vehicle_db)

@router.post("/vehicles/{vehicle_module_id}/reset-badge", status_code=http_status.HTTP_200_OK)
async def api_reset_badge_count(
    vehicle_module_id: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Reset the badge count for a specific vehicle's push notifications.
    This is typically called when a user opens the app to clear notification badges.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail=f"Vehicle '{vehicle_module_id.upper()}' not found.")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to reset badge count for this vehicle")

    # Reset badge count in background
    success = await run_in_threadpool(widget_push_service.reset_badge_count, vehicle_db.vehicle_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to reset badge count")

    return {
        "status": "success",
        "vehicle_id": vehicle_db.vehicle_id,
        "message": "Badge count reset to 0"
    }

@router.post("/user/reset-all-badges", status_code=http_status.HTTP_200_OK,
             dependencies=[Depends(require_active_api_user)])
async def api_reset_all_badge_counts(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Reset badge counts for ALL vehicles owned by the current user.
    This is typically called when a user opens the app to clear all notification badges.
    """
    # Reset badge counts for all user's vehicles in background
    vehicles_reset = await run_in_threadpool(widget_push_service.reset_all_badge_counts_for_user, current_user.id)

    return {
        "status": "success",
        "user_id": current_user.id,
        "vehicles_reset": vehicles_reset,
        "message": f"Badge counts reset for {vehicles_reset} vehicles"
    }

class UnifiedPushRegisterRequest(BaseModel):
    endpoint: str = Field(..., max_length=500, description="UnifiedPush endpoint URL provided by the distributor app.")
    device_id: Optional[str] = Field(None, max_length=64, description="Persistent device identifier (UUID) from the app.")

    @field_validator('endpoint')
    @classmethod
    def validate_endpoint(cls, v):
        from app.models.api import _validate_push_endpoint_url
        return _validate_push_endpoint_url(v)

class FcmRegisterRequest(BaseModel):
    token: str = Field(..., max_length=255, description="Firebase Cloud Messaging device token.")
    device_id: Optional[str] = Field(None, max_length=64, description="Persistent device identifier (UUID) from the app.")

@router.post("/vehicles/{vehicle_module_id}/push/unified", status_code=http_status.HTTP_200_OK)
def api_register_unified_push_endpoint(
    vehicle_module_id: str,
    body: UnifiedPushRegisterRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Register or update a UnifiedPush endpoint for a vehicle.
    Called by the Flutter-OVMS app after receiving an endpoint URL from its UnifiedPush distributor.
    When device_id is provided, the subscription is tracked per-device in push_subscriptions.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail=f"Vehicle '{vehicle_module_id.upper()}' not found.")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to register push endpoint for this vehicle")

    device_id = body.device_id or 'legacy'
    logger.debug(
        f"UnifiedPush registration request for vehicle {vehicle_module_id.upper()}: "
        f"device_id={device_id[:8]}..., "
        f"endpoint={body.endpoint[:60]}{'...' if len(body.endpoint) > 60 else ''}"
    )

    # Update legacy vehicle-level fields for backward compatibility
    vehicle_db.unified_push_endpoint = body.endpoint
    vehicle_db.enable_unified_push_notifications = True
    # Insert/update per-device subscription row (removes conflicting FCM subscription for this device)
    crud.push_subscription.upsert_subscription(db, vehicle_db.id, device_id, 'up', body.endpoint)
    db.commit()

    logger.info(f"UnifiedPush endpoint registered for vehicle {vehicle_db.vehicle_id} (device={device_id[:8]})")
    return {
        "status": "success",
        "vehicle_id": vehicle_db.vehicle_id,
        "message": "UnifiedPush endpoint registered"
    }

@router.post("/vehicles/{vehicle_module_id}/push/fcm", status_code=http_status.HTTP_200_OK)
def api_register_fcm_token(
    vehicle_module_id: str,
    body: FcmRegisterRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Register or update a Firebase Cloud Messaging token for a vehicle.
    When device_id is provided, the subscription is tracked per-device in push_subscriptions.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=404, detail=f"Vehicle '{vehicle_module_id.upper()}' not found.")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to register push token for this vehicle")

    device_id = body.device_id or 'legacy'
    logger.debug(
        f"FCM registration request for vehicle {vehicle_module_id.upper()}: "
        f"device_id={device_id[:8]}..., token={body.token[:10]}..."
    )

    # Update legacy vehicle-level fields for backward compatibility
    vehicle_db.fcm_token = body.token
    vehicle_db.enable_fcm_notifications = True
    # Insert/update per-device subscription row (removes conflicting UP subscription for this device)
    crud.push_subscription.upsert_subscription(db, vehicle_db.id, device_id, 'fcm', body.token)
    db.commit()

    logger.info(f"FCM token registered for vehicle {vehicle_db.vehicle_id} (device={device_id[:8]})")
    return {
        "status": "success",
        "vehicle_id": vehicle_db.vehicle_id,
        "message": "FCM token registered"
    }

# --- Vehicle logs & notification targets -------------------------------------------

_DATALOG_MAX_PAGE_SIZE = 200
_LOG_MAX_LIMIT = 200

_LOG_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

_CREDENTIAL_ENDPOINT_TYPES = frozenset({'fcm', 'apns', 'up'})


def _push_subscription_info(sub: models_db.PushSubscription) -> models_api.PushSubscriptionInfo:
    """The one place a PushSubscription row becomes a response body.

    Shared by the list and the create path so a new push type cannot be added to one
    projection and forgotten in the other — which is exactly how 'up' came to be
    returned in full while 'fcm' and 'apns' were redacted.
    """
    return models_api.PushSubscriptionInfo(
        id=sub.id,
        push_type=sub.push_type,
        device_id=sub.device_id,
        endpoint=None if sub.push_type in _CREDENTIAL_ENDPOINT_TYPES else sub.endpoint,
        ntfy_server_url=sub.ntfy_server_url,
        has_auth=bool(sub.ntfy_auth_token or sub.ntfy_auth_password),
        created_at=sub.created_at,
    )


def _get_owned_vehicle_or_404(
    db: Session, current_user: models_db.User, vehicle_module_id: str
) -> models_db.Vehicle:
    """Resolve a module id to a vehicle the caller may read, or raise.

    Mirrors `_get_datalog_vehicle_or_raise` in the UI router. 404 before 403 is
    deliberate and matches the rest of this file.
    """
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_module_id.upper())
    if not vehicle_db:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Vehicle not found")
    if not current_user.is_admin and vehicle_db.owner_id != current_user.id:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this vehicle",
        )
    return vehicle_db


def _log_protocol(record_type: str) -> str:
    """V3 records are stored with a 'V3' prefix on the record type; everything else is V2."""
    return 'v3' if record_type.startswith('V3') else 'v2'


@router.get("/vehicles/{vehicle_module_id}/datalogs", response_model=models_api.DataLogSummaryResponse,
            dependencies=[Depends(require_active_api_user)])
def api_get_datalog_types(
    vehicle_module_id: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """Which history record types this vehicle has stored, and how many of each.

    Crash and debug records are excluded — they have their own endpoint and a shape
    that has nothing to do with the comma-separated data records.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    types = []
    for row in crud.historical_data.get_historical_summary(db, vehicle_db.vehicle_id):
        record_type = row['h_recordtype']
        lowered = record_type.lower()
        if 'crash' in lowered or 'debug' in lowered:
            continue
        definition = DATALOG_DEFINITIONS.get(record_type)
        types.append(models_api.DataLogTypeInfo(
            record_type=record_type,
            description=definition["description"] if definition else None,
            fields=definition["fields"] if definition else [],
            total_records=row['totalrecs'],
            distinct_records=row['distinctrecs'],
            first=row['first_dt'],
            last=row['last_dt'],
        ))

    return models_api.DataLogSummaryResponse(vehicle_id=vehicle_db.vehicle_id, types=types)


@router.get("/vehicles/{vehicle_module_id}/datalogs/records", response_model=models_api.DataLogRecordsResponse,
            dependencies=[Depends(require_active_api_user)])
def api_get_datalog_records(
    vehicle_module_id: str,
    type: str = Query(..., min_length=1, max_length=50, description="Record type, e.g. '*-LOG-Trip'."),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=_DATALOG_MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """One page of the records of a single type, newest first.

    `type` is a query parameter rather than a path segment because record types contain
    '*' and '/'-unsafe characters ('*-LOG-Trip'), and `page_size` is capped: the
    per-vehicle row quota is 10 000 x 64 KiB, so an unbounded page is an OOM primitive
    for any authenticated caller (see tests/test_history_dump_bounded.py).
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    # One row over the page, so "is there more" needs no second count query.
    records_db = crud.historical_data.get_historical_data_for_vehicle(
        db, vehicle_db.vehicle_id, record_type_equals=type,
        skip=(page - 1) * page_size, limit=page_size + 1,
    )
    has_more = len(records_db) > page_size

    records = []
    max_fields = 0
    for log in records_db[:page_size]:
        fields = log.data_payload.split(',') if log.data_payload else []
        max_fields = max(max_fields, len(fields))
        records.append(models_api.DataLogRecord(
            timestamp=log.timestamp, record_number=log.record_number, fields=fields,
        ))

    definition = DATALOG_DEFINITIONS.get(type)
    field_names = definition["fields"] if definition else []
    headers = [field_names[i] if i < len(field_names) else f"F{i + 1}" for i in range(max_fields)]

    return models_api.DataLogRecordsResponse(
        vehicle_id=vehicle_db.vehicle_id,
        record_type=type,
        description=definition["description"] if definition else None,
        headers=headers,
        records=records,
        page=page,
        page_size=page_size,
        has_more=has_more,
    )


@router.get("/vehicles/{vehicle_module_id}/logs", response_model=models_api.VehicleLogsResponse,
            dependencies=[Depends(require_active_api_user)])
def api_get_vehicle_logs(
    vehicle_module_id: str,
    limit: int = Query(50, ge=1, le=_LOG_MAX_LIMIT, description="Maximum entries per category."),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """Crash reports and debug records, parsed into fields.

    Same two queries the vehicle detail page runs, with the same '%Crash%' / '%Debug%'
    split — debug excludes crash so a record is never reported twice.

    Two bounds apply and the response says which one stopped it. `limit` caps rows per
    category; _LOG_MAX_RESPONSE_BYTES caps the payload actually assembled, because a
    row here is not a small thing — a debug record carries up to 64 KiB, so the row
    cap alone permits a ~25 MB answer built entirely in memory. Crash reports spend the
    budget first: they are why someone calls this endpoint, and a debug dump must not
    crowd them out of it.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    crash_rows = crud.historical_data.get_historical_data_for_vehicle(
        db, vehicle_db.vehicle_id, record_type_like="%Crash%", limit=limit
    )
    debug_rows = crud.historical_data.get_historical_data_for_vehicle(
        db, vehicle_db.vehicle_id, record_type_like="%Debug%",
        exclude_record_type_like="%Crash%", limit=limit
    )

    budget = _LOG_MAX_RESPONSE_BYTES
    truncated = False

    crash_logs = []
    for log in crash_rows:
        cost = len(log.data_payload or "")
        if crash_logs and cost > budget:
            truncated = True
            break
        budget -= cost
        parsed = parse_crash_log_data(log.data_payload)
        crash_logs.append(models_api.CrashLogEntry(
            timestamp=log.timestamp,
            record_type=log.record_type,
            protocol=_log_protocol(log.record_type),
            firmware=parsed.get('firmware'),
            build_id=parsed.get('build_id'),
            reason_code=parsed.get('reason_code'),
            reason_text=parsed.get('reason_text'),
            is_abort=bool(parsed.get('is_abort')),
            pc=parsed.get('pc'),
            exc_cause=parsed.get('exc_cause'),
            crash_task_name=parsed.get('crash_task_name'),
            crash_task_prio=parsed.get('crash_task_prio'),
            running_task_name=parsed.get('running_task_name'),
            running_task_prio=parsed.get('running_task_prio'),
            backtrace=parsed.get('backtrace'),
        ))

    debug_logs = []
    for log in debug_rows:
        data = log.data_payload or ""
        if len(data) > budget:
            truncated = True
            break
        budget -= len(data)
        debug_logs.append(models_api.DebugLogEntry(
            timestamp=log.timestamp,
            record_type=log.record_type,
            protocol=_log_protocol(log.record_type),
            data=data,
        ))

    if truncated:
        logger.info(
            f"Vehicle logs for {vehicle_db.vehicle_id} truncated at "
            f"{_LOG_MAX_RESPONSE_BYTES} bytes ({len(crash_logs)} crash, "
            f"{len(debug_logs)} debug of up to {limit} each)."
        )

    return models_api.VehicleLogsResponse(
        vehicle_id=vehicle_db.vehicle_id, crash_logs=crash_logs, debug_logs=debug_logs,
        truncated=truncated,
    )


@router.get("/vehicles/{vehicle_module_id}/push/subscriptions",
            response_model=models_api.PushSubscriptionListResponse,
            dependencies=[Depends(require_active_api_user)])
def api_list_push_subscriptions(
    vehicle_module_id: str,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """The vehicle's notification targets, newest first.

    Push tokens, UnifiedPush endpoints and ntfy credentials are not projected — see
    _push_subscription_info.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    subscriptions = [
        _push_subscription_info(sub)
        for sub in crud.push_subscription.get_subscriptions_for_vehicle(db, vehicle_db.id)
    ]

    return models_api.PushSubscriptionListResponse(
        vehicle_id=vehicle_db.vehicle_id, subscriptions=subscriptions,
    )


@router.delete("/vehicles/{vehicle_module_id}/push/subscriptions/{subscription_id}",
               status_code=http_status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_active_api_user)])
def api_delete_push_subscription(
    vehicle_module_id: str,
    subscription_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """Remove one notification target.

    The delete is scoped to the vehicle in SQL as well as by the ownership check, so a
    subscription id belonging to someone else's vehicle deletes nothing and answers 404.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    if not crud.push_subscription.delete_subscription(db, subscription_id, vehicle_db.id):
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return None


class EmailRecipientRequest(BaseModel):
    """A manually added e-mail recipient for a vehicle's notifications.

    Validated with the same helper the web form uses. That check is the security
    boundary, not a convenience: the address is handed to the SMTP layer, and
    Python's default e-mail policy serialises a header containing CR/LF verbatim —
    so an unchecked value lets the submitter append their own headers (an extra
    Bcc:, a forged From:, a second body) and turns the server into an open relay
    sending from its own domain.
    """
    email: str = Field(..., max_length=MAX_EMAIL_LENGTH)

    @field_validator('email')
    @classmethod
    def validate_recipient(cls, v):
        return validate_email_address(v)


@router.post("/vehicles/{vehicle_module_id}/push/email",
             response_model=models_api.PushSubscriptionInfo,
             status_code=http_status.HTTP_201_CREATED,
             dependencies=[Depends(require_active_api_user)])
def api_add_email_recipient(
    vehicle_module_id: str,
    body: EmailRecipientRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """Add an e-mail address to this vehicle's notification targets.

    Keyed by the address, so adding one twice updates the existing row rather
    than accumulating duplicates, and the per-vehicle subscription cap applies
    exactly as it does to a device registration.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    subscription = crud.push_subscription.add_manual_email(db, vehicle_db.id, body.email)
    db.commit()
    db.refresh(subscription)

    logger.info(f"E-mail recipient added for vehicle {vehicle_db.vehicle_id}")
    return _push_subscription_info(subscription)


class NtfySubscriptionRequest(BaseModel):
    """A manually added ntfy target, mirroring the web form's fields.

    [server_url] goes through the same SSRF check as everywhere else: the server
    fetches this URL itself, so an unvalidated one turns a notification into a
    request to whatever the submitter names — a link-local metadata endpoint, a
    service on the loopback interface, a host inside the deployment's network.

    The topic is capped at the length `add_manual_ntfy` keys the row on. Beyond
    that the key truncates while the delivered topic does not, so two different
    topics sharing a 255-character prefix would silently become one target.
    """
    topic: str = Field(..., min_length=1, max_length=255)
    server_url: Optional[str] = Field(None, max_length=255)
    auth_method: Optional[str] = Field(None, max_length=50)
    auth_token: Optional[str] = Field(None, max_length=255)
    auth_user: Optional[str] = Field(None, max_length=100)
    auth_password: Optional[str] = Field(None, max_length=100)
    auth_query_param_name: Optional[str] = Field(None, max_length=50)

    @field_validator('topic')
    @classmethod
    def strip_topic(cls, v):
        topic = v.strip()
        if not topic:
            raise ValueError('ntfy topic cannot be empty')
        return topic

    @field_validator('server_url')
    @classmethod
    def validate_server_url(cls, v):
        return models_api._validate_ntfy_server_url(v)

    @field_validator('auth_method')
    @classmethod
    def normalise_auth_method(cls, v):
        # The form's "no authentication" option posts an empty value or "none";
        # both mean the same absence to add_manual_ntfy.
        if v is None or v.strip() == '' or v.strip().lower() == 'none':
            return None
        if v not in ('bearer', 'basic', 'query'):
            raise ValueError("auth_method must be one of 'bearer', 'basic', 'query'")
        return v


@router.post("/vehicles/{vehicle_module_id}/push/ntfy",
             response_model=models_api.PushSubscriptionInfo,
             status_code=http_status.HTTP_201_CREATED,
             dependencies=[Depends(require_active_api_user)])
def api_add_ntfy_subscription(
    vehicle_module_id: str,
    body: NtfySubscriptionRequest,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """Add an ntfy topic to this vehicle's notification targets.

    Keyed by the topic, so adding the same one again updates its server and
    credentials rather than accumulating duplicates. The credentials are stored
    encrypted and are never read back out — see PushSubscriptionInfo.
    """
    vehicle_db = _get_owned_vehicle_or_404(db, current_user, vehicle_module_id)

    subscription = crud.push_subscription.add_manual_ntfy(
        db, vehicle_db.id,
        topic=body.topic,
        server_url=body.server_url,
        auth_method=body.auth_method,
        auth_token=body.auth_token or None,
        auth_user=body.auth_user or None,
        auth_password=body.auth_password or None,
        auth_query_param_name=body.auth_query_param_name or None,
    )
    db.commit()
    db.refresh(subscription)

    logger.info(f"ntfy target added for vehicle {vehicle_db.vehicle_id}")
    return _push_subscription_info(subscription)
