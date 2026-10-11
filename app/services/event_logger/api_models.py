from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel

from app.utils.timestamps import UtcDatetime
from app.services.charge_logger.api_models import PaginationDetails


class VehicleEventSummary(BaseModel):
    id: UUID
    # `climate` or `aux_charge`; a client shows an unknown kind generically.
    kind: str
    start_time: UtcDatetime
    end_time: Optional[UtcDatetime] = None
    duration_seconds: Optional[int] = None
    start_soc: Optional[float] = None
    end_soc: Optional[float] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    cabin_temp_start: Optional[float] = None
    cabin_temp_end: Optional[float] = None
    cabin_setpoint: Optional[float] = None
    ambient_temp: Optional[float] = None
    aux_charged: bool = False
    aux_voltage_start: Optional[float] = None
    aux_voltage_end: Optional[float] = None
    aux_energy_wh: Optional[float] = None
    source: str = "metric"
    # Open *and* being recorded now, as for a charge.
    in_progress: bool = False

    class Config:
        from_attributes = True


class PaginatedVehicleEventSummary(BaseModel):
    pagination: PaginationDetails
    events: List[VehicleEventSummary]
