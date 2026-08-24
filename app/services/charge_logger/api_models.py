from pydantic import BaseModel, field_serializer
from typing import Optional, List
import datetime
from uuid import UUID

class ChargeLogPoint(BaseModel):
    timestamp: datetime.datetime
    soc: Optional[float] = None
    power_kw: Optional[float] = None
    battery_temp_c: Optional[float] = None

    @field_serializer('timestamp')
    def serialize_timestamp(self, dt: datetime.datetime) -> str:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.isoformat()

    class Config:
        from_attributes = True

class ChargeLogSummary(BaseModel):
    id: UUID
    start_time: datetime.datetime
    end_time: Optional[datetime.datetime] = None
    duration_seconds: Optional[int] = None
    start_soc: Optional[float] = None
    end_soc: Optional[float] = None
    start_latitude: Optional[float] = None
    start_longitude: Optional[float] = None
    start_odometer: Optional[float] = None
    energy_added_kwh: Optional[float] = None
    max_power_kw: Optional[float] = None
    average_power_kw: Optional[float] = None

    @field_serializer('start_time', 'end_time')
    def serialize_datetimes(self, dt: Optional[datetime.datetime]) -> Optional[str]:
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.isoformat()

    class Config:
        from_attributes = True

class ChargeLogDetail(ChargeLogSummary):
    points: List[ChargeLogPoint] = []

class PaginationDetails(BaseModel):
    total_items: int
    total_pages: int
    current_page: int
    limit: int

class PaginatedChargeLogSummary(BaseModel):
    pagination: PaginationDetails
    charges: List[ChargeLogSummary]

class ChargeStatisticsTotals(BaseModel):
    total_charges: int
    total_energy_kwh: float
    total_duration_seconds: int
    average_energy_kwh: float
    average_duration_seconds: int
    total_soc_gained: float
    average_soc_gained: float

class ChargeStatisticsMonthly(BaseModel):
    period: datetime.date
    total_charges: int
    total_energy_kwh: float

class ChargeStatistics(BaseModel):
    total: ChargeStatisticsTotals
    monthly: List[ChargeStatisticsMonthly]