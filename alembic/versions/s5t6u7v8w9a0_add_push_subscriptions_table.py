"""Add push_subscriptions table for per-device push notification tracking

Revision ID: s5t6u7v8w9a0
Revises: r4s5t6u7v8w9
Create Date: 2026-05-23 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column, select


revision: str = 's5t6u7v8w9a0'
down_revision: Union[str, None] = 'r4s5t6u7v8w9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'push_subscriptions',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('vehicle_id_fk', sa.Integer(), sa.ForeignKey('vehicles.id', name='fk_pushsub_vehicle_id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('device_id', sa.String(64), nullable=False),
        sa.Column('push_type', sa.String(10), nullable=False),
        sa.Column('endpoint', sa.String(500), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('vehicle_id_fk', 'device_id', 'push_type', name='uq_pushsub_vehicle_device_type'),
    )
    op.create_index('ix_pushsub_vehicle_type', 'push_subscriptions', ['vehicle_id_fk', 'push_type'])

    # Migrate existing per-vehicle tokens to the new table as 'legacy' device rows.
    # References to vehicles and push_subscriptions tables for data migration.
    vehicles = table(
        'vehicles',
        column('id', sa.Integer),
        column('fcm_token', sa.String),
        column('apns_token', sa.String),
        column('unified_push_endpoint', sa.String),
        column('enable_fcm_notifications', sa.Boolean),
        column('enable_apns_notifications', sa.Boolean),
        column('enable_unified_push_notifications', sa.Boolean),
    )
    push_subscriptions = table(
        'push_subscriptions',
        column('vehicle_id_fk', sa.Integer),
        column('device_id', sa.String),
        column('push_type', sa.String),
        column('endpoint', sa.String),
    )

    conn = op.get_bind()
    rows = conn.execute(select(
        vehicles.c.id,
        vehicles.c.fcm_token,
        vehicles.c.apns_token,
        vehicles.c.unified_push_endpoint,
        vehicles.c.enable_fcm_notifications,
        vehicles.c.enable_apns_notifications,
        vehicles.c.enable_unified_push_notifications,
    )).fetchall()

    inserts = []
    for row in rows:
        vid = row[0]
        if row[4] and row[1]:  # enable_fcm and fcm_token
            inserts.append({'vehicle_id_fk': vid, 'device_id': 'legacy', 'push_type': 'fcm', 'endpoint': row[1]})
        if row[5] and row[2]:  # enable_apns and apns_token
            inserts.append({'vehicle_id_fk': vid, 'device_id': 'legacy', 'push_type': 'apns', 'endpoint': row[2]})
        if row[6] and row[3]:  # enable_up and unified_push_endpoint
            inserts.append({'vehicle_id_fk': vid, 'device_id': 'legacy', 'push_type': 'up', 'endpoint': row[3]})

    if inserts:
        op.bulk_insert(push_subscriptions, inserts)


def downgrade() -> None:
    op.drop_index('ix_pushsub_vehicle_type', table_name='push_subscriptions')
    op.drop_table('push_subscriptions')
