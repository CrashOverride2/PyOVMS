from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from app.database import Base
import uuid

# What a vehicle event is. Stored as text so an older app reading a newer kind sees
# an unknown word rather than a wrong number.
KIND_CLIMATE = "climate"
KIND_AUX_CHARGE = "aux_charge"


class VehicleEvent(Base):
    """Something the parked vehicle did on its own: climate while parked (`climate`)
    or 12 V charging through the DC/DC converter (`aux_charge`). A climate event that
    ran the converter is one event with `aux_charged` set.
    """

    __tablename__ = "vehicle_events"

    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vehicle_id_fk = Column(
        Integer,
        ForeignKey("vehicles.id", name="fk_vehicle_events_vehicle_id_fk_vehicles", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    kind = Column(String(16), nullable=False)

    start_time = Column(DateTime(timezone=True), nullable=False, index=True)
    end_time = Column(DateTime(timezone=True), nullable=True)
    # The last time the vehicle was heard while the event was open. Where an orphaned
    # row is closed: there are no points to say where it got to.
    last_activity = Column(DateTime(timezone=True), nullable=True)

    start_soc = Column(Float, nullable=True)
    end_soc = Column(Float, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)

    cabin_temp_start = Column(Float, nullable=True)
    cabin_temp_end = Column(Float, nullable=True)
    cabin_setpoint = Column(Float, nullable=True)
    ambient_temp = Column(Float, nullable=True)

    aux_charged = Column(Boolean, nullable=False, default=False)
    aux_voltage_start = Column(Float, nullable=True)
    aux_voltage_end = Column(Float, nullable=True)
    aux_energy_wh = Column(Float, nullable=True)

    # What the event was recognised from: `metric`, `event` (the module's own event
    # topics), or `both`.
    source = Column(String(8), nullable=False, default="metric")
