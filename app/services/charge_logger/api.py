import logging
import math
import csv
import io
from typing import Iterator
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from . import crud, gpx_generator, kml_generator
from .api_models import PaginatedChargeLogSummary, PaginationDetails, ChargeLogDetail, ChargeStatistics
from .charge_manager import charge_manager
from app.services.event_logger import crud as event_crud
from app.services.event_logger.api_models import PaginatedVehicleEventSummary, VehicleEventSummary
from app.services.event_logger.event_manager import event_manager
from .database import get_db
from .security import get_current_user
from app.models.db import User as OvmsUser
from app.utils.csv_safety import sanitize_csv_row

logger = logging.getLogger(__name__)

# Machine-readable `detail` of a charge log that is not there for this user, so a
# client can tell it from any other 404.
CHARGE_LOG_NOT_FOUND = "charge_log_not_found"


def _owned_charge_log(db: Session, charge_log_id: UUID, user_id: int):
    """
    The charge log, or 404 — for one that does not exist and for another account's alike.
    A 403 for the second confirmed that the id exists, a membership oracle over UUIDs that
    turn up in shared links and logs. Karto answers trips the same way (`_authorize_trip`).
    """
    charge_log = crud.get_charge_log_details(db, charge_log_id=charge_log_id)
    if (not charge_log or not charge_log.vehicle
            or not crud.check_vehicle_ownership(db, user_id=user_id,
                                                vehicle_id=charge_log.vehicle.vehicle_id)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=CHARGE_LOG_NOT_FOUND)
    return charge_log


# The `detail` of a vehicle event that is not there for this user, as for a charge log.
VEHICLE_EVENT_NOT_FOUND = "event_not_found"


def _owned_event(db: Session, event_id: UUID, user_id: int):
    event = event_crud.get_event(db, event_id)
    vehicle_id = event_crud.vehicle_id_of(db, event) if event else None
    if (event is None or vehicle_id is None
            or not crud.check_vehicle_ownership(db, user_id=user_id, vehicle_id=vehicle_id)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=VEHICLE_EVENT_NOT_FOUND)
    return event


def _event_summary(event, recording=None) -> VehicleEventSummary:
    summary = VehicleEventSummary.model_validate(event)
    summary.duration_seconds = event_crud.duration_seconds(event)
    if event.end_time is not None:
        summary.in_progress = False
    elif recording is not None:
        summary.in_progress = event.id in recording
    else:
        summary.in_progress = event_manager.is_event_active(event.id)
    return summary


router = APIRouter(
    prefix="/api/chargelogs/v1",
    tags=["Charge Logging API"],
    dependencies=[Depends(get_current_user)],
    responses={
        401: {"description": "Authentication required"},
        403: {"description": "Insufficient permissions"},
    },
)

@router.get("/vehicles/{vehicle_id}/charges", response_model=PaginatedChargeLogSummary)
def get_charge_logs_for_vehicle(
    vehicle_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=vehicle_id.upper()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this vehicle's charge logs")

    charges, total_items = crud.get_charge_logs_for_vehicle(
        db, vehicle_id=vehicle_id.upper(), limit=limit, offset=(page - 1) * limit
    )
    
    total_pages = math.ceil(total_items / limit) if total_items > 0 else 1
    for charge in charges:
        charge.in_progress = charge.end_time is None and charge_manager.is_session_active(charge.id)

    return PaginatedChargeLogSummary(
        pagination=PaginationDetails(
            total_items=total_items,
            total_pages=total_pages,
            current_page=page,
            limit=limit
        ),
        charges=charges
    )

@router.get("/charges/{charge_log_id}", response_model=ChargeLogDetail)
def get_charge_log_details(
    charge_log_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    charge_log = _owned_charge_log(db, charge_log_id, current_user.id)
    
    charge_detail = ChargeLogDetail.from_orm(charge_log)
    if charge_detail.end_time and charge_detail.start_time:
        duration = charge_detail.end_time - charge_detail.start_time
        charge_detail.duration_seconds = int(duration.total_seconds())
    charge_detail.in_progress = charge_detail.end_time is None and charge_manager.is_session_active(charge_detail.id)

    return charge_detail

@router.delete("/charges/{charge_log_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_charge_log(
    charge_log_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    """
    Deletes a specific charge log and all its associated data points.
    Ensures the authenticated user has permission before deleting.
    """
    charge_log = _owned_charge_log(db, charge_log_id, current_user.id)

    # A session being recorded is not deleted under the recorder (409).
    if charge_log.end_time is None and charge_manager.is_session_active(charge_log.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Charge session is still being recorded")

    crud.delete_charge_log(db, charge_log_id=charge_log_id)
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.get("/vehicles/{vehicle_id}/stats", response_model=ChargeStatistics)
def get_charge_statistics_for_vehicle(
    vehicle_id: str,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    """
    Retrieve total and monthly charge statistics for a specific vehicle.
    """
    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=vehicle_id.upper()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this vehicle's stats")

    stats = crud.get_charge_statistics(db, vehicle_id=vehicle_id.upper())
    return stats

@router.get("/vehicles/{vehicle_id}/export", response_class=Response)
def export_charge_logs_csv(
    vehicle_id: str,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=vehicle_id.upper()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to export this vehicle's charge logs")

    charge_logs = crud.export_charge_logs_for_vehicle(db, vehicle_id=vehicle_id.upper())

    def iter_csv() -> Iterator[str]:
        output = io.StringIO()
        writer = csv.writer(output)
        
        header = [
            "id", "start_time_utc", "end_time_utc", "duration_seconds",
            "start_soc", "end_soc", "energy_added_kwh", "max_power_kw", "average_power_kw",
            "start_odometer_km", "start_latitude", "start_longitude"
        ]
        writer.writerow(header)
        yield output.getvalue()
        output.seek(0)
        output.truncate(0)

        for log in charge_logs:
            duration = (log.end_time - log.start_time).total_seconds() if log.end_time and log.start_time else None
            row = [
                log.id,
                log.start_time.strftime('%Y-%m-%d %H:%M:%S') if log.start_time else "",
                log.end_time.strftime('%Y-%m-%d %H:%M:%S') if log.end_time else "",
                int(duration) if duration is not None else "",
                log.start_soc, log.end_soc, log.energy_added_kwh,
                log.max_power_kw, log.average_power_kw,
                log.start_odometer, log.start_latitude, log.start_longitude
            ]
            # Every column here is currently a number or a formatted timestamp, so
            # nothing can start a formula today. It goes through the sanitizer anyway,
            # because the next column added to this list will not come back here to
            # ask — the vehicle CSV exports learned that the same way.
            writer.writerow(sanitize_csv_row(row))
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

    filename = f"charge_logs_{vehicle_id.upper()}.csv"
    return StreamingResponse(iter_csv(), media_type="text/csv", headers={'Content-Disposition': f'attachment; filename="{filename}"'})

@router.get("/charges/{charge_log_id}/gpx", response_class=Response)
def export_charge_location_gpx(
    charge_log_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    """
    Export the charge session start location as a GPX waypoint file.
    """
    charge_log = _owned_charge_log(db, charge_log_id, current_user.id)

    if charge_log.start_latitude is None or charge_log.start_longitude is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No location data available for this charge session")

    try:
        gpx_content = gpx_generator.generate_gpx_for_charge(charge_log)
    except Exception as e:
        logger.error(f"Error generating GPX for charge {charge_log_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate GPX file")

    return Response(
        content=gpx_content,
        media_type="application/gpx+xml",
        headers={
            "Content-Disposition": f'attachment; filename="charge_{charge_log_id}.gpx"'
        }
    )

@router.get("/charges/{charge_log_id}/kml", response_class=Response)
def export_charge_location_kml(
    charge_log_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    """
    Export the charge session start location as a KML placemark file.
    """
    charge_log = _owned_charge_log(db, charge_log_id, current_user.id)

    if charge_log.start_latitude is None or charge_log.start_longitude is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No location data available for this charge session")

    try:
        kml_content = kml_generator.generate_kml_for_charge(charge_log)
    except Exception as e:
        logger.error(f"Error generating KML for charge {charge_log_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to generate KML file")

    return Response(
        content=kml_content,
        media_type="application/vnd.google-earth.kml+xml",
        headers={
            "Content-Disposition": f'attachment; filename="charge_{charge_log_id}.kml"'
        }
    )

# Climate and 12 V events of the parked vehicle; they share this router's switch,
# owner check and 404 rule.

@router.get("/vehicles/{vehicle_id}/events", response_model=PaginatedVehicleEventSummary)
def get_vehicle_events(
    vehicle_id: str,
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=vehicle_id.upper()):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to access this vehicle's events")
    events, total_items = event_crud.get_events_for_vehicle(
        db, vehicle_id=vehicle_id.upper(), limit=limit, offset=(page - 1) * limit
    )
    total_pages = math.ceil(total_items / limit) if total_items > 0 else 1
    # One look at the recorder for the page, not one lock per row.
    recording = event_manager.active_event_ids()
    return PaginatedVehicleEventSummary(
        pagination=PaginationDetails(
            total_items=total_items, total_pages=total_pages, current_page=page, limit=limit
        ),
        events=[_event_summary(e, recording) for e in events],
    )


@router.get("/events/{event_id}", response_model=VehicleEventSummary)
def get_vehicle_event(
    event_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    return _event_summary(_owned_event(db, event_id, current_user.id))


@router.delete("/events/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vehicle_event(
    event_id: UUID,
    db: Session = Depends(get_db),
    current_user: OvmsUser = Depends(get_current_user)
):
    event = _owned_event(db, event_id, current_user.id)
    # Not under the recorder, for the charge log's reason.
    if event.end_time is None and event_manager.is_event_active(event.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Event is still being recorded")
    event_crud.delete_event(db, event_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
