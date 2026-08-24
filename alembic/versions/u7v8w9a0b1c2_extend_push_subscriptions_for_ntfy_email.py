"""Extend push_subscriptions to support ntfy and email notification types

Revision ID: u7v8w9a0b1c2
Revises: t6u7v8w9a0b1
Create Date: 2026-05-24 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column, select


revision: str = 'u7v8w9a0b1c2'
down_revision: Union[str, None] = 't6u7v8w9a0b1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Widen device_id to accommodate email addresses and ntfy topics
    with op.batch_alter_table('push_subscriptions') as batch_op:
        batch_op.alter_column('device_id', type_=sa.String(255), existing_type=sa.String(64), nullable=False)
        batch_op.add_column(sa.Column('ntfy_server_url', sa.String(255), nullable=True))
        batch_op.add_column(sa.Column('ntfy_auth_method', sa.String(50), nullable=True))
        batch_op.add_column(sa.Column('ntfy_auth_token', sa.String(255), nullable=True))
        batch_op.add_column(sa.Column('ntfy_auth_user', sa.String(100), nullable=True))
        batch_op.add_column(sa.Column('ntfy_auth_password', sa.String(100), nullable=True))
        batch_op.add_column(sa.Column('ntfy_auth_query_param_name', sa.String(50), nullable=True))

    # Migrate existing per-vehicle ntfy and email config to subscription rows
    vehicles = table(
        'vehicles',
        column('id', sa.Integer),
        column('enable_ntfy_notifications', sa.Boolean),
        column('ntfy_topic', sa.String),
        column('ntfy_server_url', sa.String),
        column('ntfy_auth_method', sa.String),
        column('ntfy_auth_token', sa.String),
        column('ntfy_auth_user', sa.String),
        column('ntfy_auth_password', sa.String),
        column('ntfy_auth_query_param_name', sa.String),
        column('enable_email_notifications', sa.Boolean),
        column('notification_email', sa.String),
    )
    push_subscriptions = table(
        'push_subscriptions',
        column('vehicle_id_fk', sa.Integer),
        column('device_id', sa.String),
        column('push_type', sa.String),
        column('endpoint', sa.String),
        column('ntfy_server_url', sa.String),
        column('ntfy_auth_method', sa.String),
        column('ntfy_auth_token', sa.String),
        column('ntfy_auth_user', sa.String),
        column('ntfy_auth_password', sa.String),
        column('ntfy_auth_query_param_name', sa.String),
    )

    conn = op.get_bind()
    rows = conn.execute(select(
        vehicles.c.id,
        vehicles.c.enable_ntfy_notifications,
        vehicles.c.ntfy_topic,
        vehicles.c.ntfy_server_url,
        vehicles.c.ntfy_auth_method,
        vehicles.c.ntfy_auth_token,
        vehicles.c.ntfy_auth_user,
        vehicles.c.ntfy_auth_password,
        vehicles.c.ntfy_auth_query_param_name,
        vehicles.c.enable_email_notifications,
        vehicles.c.notification_email,
    )).fetchall()

    inserts = []
    for row in rows:
        vid = row[0]
        if row[1] and row[2]:  # enable_ntfy and ntfy_topic
            topic = row[2][:255]
            inserts.append({
                'vehicle_id_fk': vid,
                'device_id': topic,
                'push_type': 'ntfy',
                'endpoint': topic,
                'ntfy_server_url': row[3],
                'ntfy_auth_method': row[4],
                'ntfy_auth_token': row[5],
                'ntfy_auth_user': row[6],
                'ntfy_auth_password': row[7],
                'ntfy_auth_query_param_name': row[8],
            })
        if row[9] and row[10]:  # enable_email and notification_email
            email = row[10][:255]
            inserts.append({
                'vehicle_id_fk': vid,
                'device_id': email,
                'push_type': 'email',
                'endpoint': email,
                'ntfy_server_url': None,
                'ntfy_auth_method': None,
                'ntfy_auth_token': None,
                'ntfy_auth_user': None,
                'ntfy_auth_password': None,
                'ntfy_auth_query_param_name': None,
            })

    if inserts:
        op.bulk_insert(push_subscriptions, inserts)


def downgrade() -> None:
    with op.batch_alter_table('push_subscriptions') as batch_op:
        batch_op.drop_column('ntfy_auth_query_param_name')
        batch_op.drop_column('ntfy_auth_password')
        batch_op.drop_column('ntfy_auth_user')
        batch_op.drop_column('ntfy_auth_token')
        batch_op.drop_column('ntfy_auth_method')
        batch_op.drop_column('ntfy_server_url')
        batch_op.alter_column('device_id', type_=sa.String(64), existing_type=sa.String(255), nullable=False)

    # Delete migrated ntfy and email rows (downgrade loses the data)
    op.execute("DELETE FROM push_subscriptions WHERE push_type IN ('ntfy', 'email')")
