from sqlalchemy import Column, Integer, DateTime, ForeignKey, Float, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from app.database import Base
import uuid

class ChargeLog(Base):
    __tablename__ = "charge_logs"
    id = Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vehicle_id_fk = Column(Integer, ForeignKey("vehicles.id", name="fk_charge_logs_vehicle_id_fk_vehicles", ondelete="CASCADE"), nullable=False, index=True)

    start_time = Column(DateTime(timezone=True), nullable=False, index=True)
    end_time = Column(DateTime(timezone=True), nullable=True)

    start_soc = Column(Float, nullable=True)
    end_soc = Column(Float, nullable=True)

    start_latitude = Column(Float, nullable=True)
    start_longitude = Column(Float, nullable=True)
    start_odometer = Column(Float, nullable=True)

    energy_added_kwh = Column(Float, nullable=True)

    max_power_kw = Column(Float, nullable=True)
    average_power_kw = Column(Float, nullable=True)

    vehicle = relationship("app.models.db.Vehicle", back_populates="charge_logs")
    points = relationship("ChargeLogPoint", back_populates="charge_log", cascade="all, delete-orphan", order_by="ChargeLogPoint.timestamp")

class ChargeLogPoint(Base):
    __tablename__ = "charge_log_points"
    __table_args__ = (
        UniqueConstraint('charge_log_id_fk', 'timestamp', name='uq_charge_log_points_log_timestamp'),
    )

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    charge_log_id_fk = Column(PG_UUID(as_uuid=True), ForeignKey("charge_logs.id", name="fk_charge_log_points_charge_log_id_fk_charge_logs", ondelete="CASCADE"), nullable=False, index=True)

    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    soc = Column(Float, nullable=True)
    power_kw = Column(Float, nullable=True)
    battery_temp_c = Column(Float, nullable=True)

    charge_log = relationship("ChargeLog", back_populates="points")