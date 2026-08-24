from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status as http_status
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

router.include_router(users_router)
router.include_router(users_me_router)
router.include_router(apikeys_router)
router.include_router(websockets_router)
# Unauthenticated by design: this is where a device exchanges credentials for a key.
router.include_router(device_auth_router)
router.include_router(security_events_router, prefix="/security", tags=["Security Events API"])


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
    Called by the official OVMS Connect app after receiving an endpoint URL from its UnifiedPush distributor.
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