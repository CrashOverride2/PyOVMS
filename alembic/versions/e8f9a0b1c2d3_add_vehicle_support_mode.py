"""Add support mode to vehicles: an owner's time-limited grant of admin access

Revision ID: e8f9a0b1c2d3
Revises: d7e8f9a0b1c2
Create Date: 2026-10-09 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e8f9a0b1c2d3'
down_revision: Union[str, None] = 'd7e8f9a0b1c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('support_until', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('support_enabled_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('support_granted_by_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_vehicles_support_until'), ['support_until'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vehicles_support_until'))
        batch_op.drop_column('support_granted_by_id')
        batch_op.drop_column('support_enabled_at')
        batch_op.drop_column('support_until')
