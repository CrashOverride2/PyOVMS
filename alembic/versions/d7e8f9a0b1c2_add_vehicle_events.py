"""Add vehicle_events: climate and 12 V events of the parked vehicle

Revision ID: d7e8f9a0b1c2
Revises: c6d7e8f9a0b1
Create Date: 2026-10-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


revision: str = 'd7e8f9a0b1c2'
down_revision: Union[str, None] = 'c6d7e8f9a0b1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    dialect = op.get_context().dialect.name
    uuid_type = PG_UUID(as_uuid=True) if dialect == 'postgresql' else sa.String(36)

    op.create_table('vehicle_events',
        sa.Column('id', uuid_type, nullable=False),
        sa.Column('vehicle_id_fk', sa.Integer(), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_activity', sa.DateTime(timezone=True), nullable=True),
        sa.Column('start_soc', sa.Float(), nullable=True),
        sa.Column('end_soc', sa.Float(), nullable=True),
        sa.Column('latitude', sa.Float(), nullable=True),
        sa.Column('longitude', sa.Float(), nullable=True),
        sa.Column('cabin_temp_start', sa.Float(), nullable=True),
        sa.Column('cabin_temp_end', sa.Float(), nullable=True),
        sa.Column('cabin_setpoint', sa.Float(), nullable=True),
        sa.Column('ambient_temp', sa.Float(), nullable=True),
        sa.Column('aux_charged', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('aux_voltage_start', sa.Float(), nullable=True),
        sa.Column('aux_voltage_end', sa.Float(), nullable=True),
        sa.Column('aux_energy_wh', sa.Float(), nullable=True),
        sa.Column('source', sa.String(length=8), server_default='metric', nullable=False),
        sa.ForeignKeyConstraint(['vehicle_id_fk'], ['vehicles.id'],
                                name=op.f('fk_vehicle_events_vehicle_id_fk_vehicles'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vehicle_events_vehicle_id_fk'), 'vehicle_events', ['vehicle_id_fk'], unique=False)
    op.create_index(op.f('ix_vehicle_events_start_time'), 'vehicle_events', ['start_time'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_vehicle_events_start_time'), table_name='vehicle_events')
    op.drop_index(op.f('ix_vehicle_events_vehicle_id_fk'), table_name='vehicle_events')
    op.drop_table('vehicle_events')
