import logging
import time
from typing import Optional
import datetime
import requests
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.models import api as models_api, db as models_db
from app import crud
from app.connection_manager import manager as v2_manager
from app.mqtt_interactive_client import mqtt_interactive_client
from app.config import settings

# A deletion must not fail on a restarting Karto, but it must also not hang the
# request forever. Three tries with a short pause covers a rolling restart.
KARTO_DELETE_ATTEMPTS = 3
KARTO_DELETE_RETRY_SECONDS = 2.0

logger = logging.getLogger(__name__)

async def _send_v2_command(vehicle_id_upper: str, command_str: str) -> models_api.CommandResponse:
    """Sends a command via the V2/TCP protocol."""
    logger.info(f"Sending command '{command_str}' to {vehicle_id_upper} via V2/TCP.")
    response_data = await v2_manager.forward_to_car(vehicle_id_upper, command_str, source_app_conn=None)
    
    if response_data is None:
        return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="Car not connected (V2) or command could not be sent.")
    elif response_data == "TIMEOUT":
        return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="Command (V2) timed out waiting for vehicle response.")
    elif response_data == "CANCELLED":
         return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="Command (V2) processing cancelled.")
    elif response_data == "BUSY_PENDING_COMMAND":
        return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="Another V2 command of the same type is already pending for this vehicle.")

    parts = response_data.split(',')
    is_success = len(parts) > 1 and parts[1] == '0'
    return models_api.CommandResponse(
        vehicle_id=vehicle_id_upper,
        response_data=response_data,
        success=is_success,
        error_message=None if is_success else "Vehicle (V2) reported an error or non-zero status."
    )

async def _send_v3_command(vehicle: models_db.Vehicle, command_str: str) -> models_api.CommandResponse:
    """Sends a command via the V3/MQTT protocol."""
    vehicle_id_upper = vehicle.vehicle_id.upper()
    logger.info(f"Sending command '{command_str}' to {vehicle_id_upper} via V3/MQTT.")
    if not vehicle.owner or not vehicle.owner.username:
        return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="Vehicle has no owner, cannot construct MQTT topic.")
    
    return await mqtt_interactive_client.send_command(
        user=vehicle.owner.username,
        vehicle_id=vehicle_id_upper,
        command=command_str
    )


async def send_command_to_vehicle(
    vehicle: models_db.Vehicle,
    command_str: str,
    protocol_preference: Optional[str] = None
) -> models_api.CommandResponse:
    """
    Sends a command to a vehicle, intelligently choosing the protocol (V2/TCP or V3/MQTT).
    `protocol_preference` can be 'v2' or 'v3' to force a protocol if vehicle is 'both'.
    """
    vehicle_id_upper = vehicle.vehicle_id.upper()
    
    use_v2 = vehicle.protocol in ('v2', 'both')
    use_v3 = vehicle.protocol in ('v3', 'both')

    # Determine online status for each protocol
    is_v2_online = use_v2 and (vehicle_id_upper in v2_manager.car_connections)
    
    is_v3_online = False
    if use_v3 and vehicle.last_seen_v3:
        # V3 is considered online if a metric was received in the last 15 minutes.
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        last_seen_v3_aware = vehicle.last_seen_v3.replace(tzinfo=datetime.timezone.utc) if vehicle.last_seen_v3.tzinfo is None else vehicle.last_seen_v3
        if (now_utc - last_seen_v3_aware).total_seconds() < (15 * 60):
            is_v3_online = True

    # Handle explicit protocol preference first
    if protocol_preference == 'v3' and use_v3:
        return await _send_v3_command(vehicle, command_str)
    
    if protocol_preference == 'v2' and use_v2:
        if is_v2_online:
            return await _send_v2_command(vehicle_id_upper, command_str)
        else:
            return models_api.CommandResponse(vehicle_id=vehicle_id_upper, success=False, error_message="V2 protocol was preferred, but vehicle is not connected via V2/TCP.")
            
    # Default logic (no preference): Prefer V3 if available
    if use_v3 and is_v3_online:
        return await _send_v3_command(vehicle, command_str)
    
    # Fallback to V2 if V3 is not available/online
    if use_v2 and is_v2_online:
        return await _send_v2_command(vehicle_id_upper, command_str)

    # If neither protocol is online/available
    return models_api.CommandResponse(
        vehicle_id=vehicle_id_upper,
        success=False,
        error_message=f"No suitable online protocol found for vehicle. Configured: {vehicle.protocol}, V2 Online: {is_v2_online}, V3 Online: {is_v3_online}"
    )

class KartoDeletionFailed(Exception):
    """Karto could not confirm that a vehicle's trip data was removed."""


async def trigger_karto_vehicle_deletion(db: Session, vehicle_id: str, current_user: models_db.User) -> None:
    """
    Delete all trip data for a vehicle in Karto. Raises KartoDeletionFailed if it
    could not be confirmed.

    This used to be fire-and-forget: a failed call was logged and the vehicle was
    removed from the main server anyway. Karto being briefly unreachable therefore
    left the complete GPS history behind — and because a vehicle id becomes free
    again on deletion, whoever registered the same id next inherited it.

    Raising instead means the caller can keep the vehicle and let the owner retry,
    which is the only outcome that makes "delete my vehicle" mean what it says.
    """
    if not settings.ENABLE_KARTO_TRIP_TRACKING:
        return

    logger.info(f"Karto: Triggering deletion of all trip data for vehicle {vehicle_id}.")

    # 1. Create a temporary API key for this internal operation
    temp_key_name = f"temp-karto-delete-{vehicle_id}-{datetime.datetime.now(datetime.timezone.utc).timestamp()}"
    expires_delta = datetime.timedelta(minutes=1)
    db_api_key, plain_key = crud.apikey.create_api_key(
        db=db, user_id=current_user.id, name=temp_key_name, expires_delta=expires_delta,
        # Server plumbing: exists only for the duration of this call.
        purpose=crud.apikey.KeyPurpose.INTERNAL,
    )

    try:
        # 2. Construct the full URL and headers for the API call
        url = f"{settings.SERVER_BASE_URL.rstrip('/')}/api/karto/v1/vehicles/{vehicle_id}/trips"
        headers = {"X-API-Key": plain_key}

        # 3. Define the blocking request function to be run in a threadpool.
        #    Retries a few times: the common failure is a restarting Karto, not a
        #    permanent one, and a transient blip must not cost the user their
        #    deletion.
        def do_delete_request():
            last_error = None
            for attempt in range(1, KARTO_DELETE_ATTEMPTS + 1):
                try:
                    response = requests.delete(url, headers=headers, timeout=30)
                    response.raise_for_status()
                    logger.info(
                        f"Karto: trip data for vehicle {vehicle_id} deleted "
                        f"(status {response.status_code}, attempt {attempt})."
                    )
                    return
                except requests.RequestException as e:
                    last_error = e
                    logger.warning(
                        f"Karto: deletion attempt {attempt}/{KARTO_DELETE_ATTEMPTS} for "
                        f"vehicle {vehicle_id} failed: {e}"
                    )
                    if attempt < KARTO_DELETE_ATTEMPTS:
                        time.sleep(KARTO_DELETE_RETRY_SECONDS)
            raise KartoDeletionFailed(
                f"Karto did not confirm deletion of trip data for {vehicle_id}: {last_error}"
            )

        # 4. Execute the request in a non-blocking way
        await run_in_threadpool(do_delete_request)

    finally:
        # 5. Ensure the temporary API key is deleted
        crud.apikey.delete_api_key_by_id_and_user(db, api_key_id=db_api_key.id, user_id=current_user.id)
        logger.debug("Karto: Cleaned up temporary API key used for vehicle deletion.")


async def trigger_karto_deletion_for_user_vehicles(
    db: Session, user: models_db.User, acting_user: models_db.User
) -> None:
    """
    Delete the Karto trip data of every vehicle this user owns. Raises
    KartoDeletionFailed if any of them could not be confirmed.

    Must be called *before* the user row goes away: it needs the vehicles to still be
    there, and Karto authorises the call against the vehicle's current registration.
    """
    if not settings.ENABLE_KARTO_TRIP_TRACKING:
        return

    vehicle_ids = [
        v.vehicle_id
        for v in db.query(models_db.Vehicle).filter(models_db.Vehicle.owner_id == user.id).all()
    ]
    if not vehicle_ids:
        return

    logger.info(
        f"Karto: deleting trip data for {len(vehicle_ids)} vehicle(s) of user "
        f"'{user.username}' before the account is removed."
    )
    for vehicle_id in vehicle_ids:
        await trigger_karto_vehicle_deletion(db, vehicle_id, acting_user)