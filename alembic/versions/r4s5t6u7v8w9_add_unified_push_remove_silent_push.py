"""Add unified push, remove silent push notifications

Revision ID: r4s5t6u7v8w9
Revises: q3r4s5t6u7v8
Create Date: 2026-05-08 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'r4s5t6u7v8w9'
down_revision: Union[str, None] = 'q3r4s5t6u7v8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column('vehicles', 'enable_silent_push_notifications')
    op.add_column('vehicles', sa.Column('enable_unified_push_notifications', sa.Boolean(), nullable=False, server_default='0'))
    op.add_column('vehicles', sa.Column('unified_push_endpoint', sa.String(500), nullable=True))


def downgrade() -> None:
    op.drop_column('vehicles', 'unified_push_endpoint')
    op.drop_column('vehicles', 'enable_unified_push_notifications')
    op.add_column('vehicles', sa.Column('enable_silent_push_notifications', sa.Boolean(), nullable=False, server_default='1'))
