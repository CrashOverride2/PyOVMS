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
from .database import get_db
from .security import get_current_user
from app.models.db import User as OvmsUser
from app.utils.csv_safety import sanitize_csv_row

logger = logging.getLogger(__name__)

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
    charge_log = crud.get_charge_log_details(db, charge_log_id=charge_log_id)
    if not charge_log or not charge_log.vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Charge log not found")

    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=charge_log.vehicle.vehicle_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this charge log")
    
    charge_detail = ChargeLogDetail.from_orm(charge_log)
    if charge_detail.end_time and charge_detail.start_time:
        duration = charge_detail.end_time - charge_detail.start_time
        charge_detail.duration_seconds = int(duration.total_seconds())

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
    charge_log = crud.get_charge_log_details(db, charge_log_id=charge_log_id)
    if not charge_log or not charge_log.vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Charge log not found")

    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=charge_log.vehicle.vehicle_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete this charge log")

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
    charge_log = crud.get_charge_log_details(db, charge_log_id=charge_log_id)
    if not charge_log or not charge_log.vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Charge log not found")

    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=charge_log.vehicle.vehicle_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to export this charge log")

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
    charge_log = crud.get_charge_log_details(db, charge_log_id=charge_log_id)
    if not charge_log or not charge_log.vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Charge log not found")

    if not crud.check_vehicle_ownership(db, user_id=current_user.id, vehicle_id=charge_log.vehicle.vehicle_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to export this charge log")

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