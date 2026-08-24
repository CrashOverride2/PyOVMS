"""Add unit_preference to user

Revision ID: q3r4s5t6u7v8
Revises: p2q3r4s5t6u7
Create Date: 2026-05-07 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'q3r4s5t6u7v8'
down_revision: Union[str, None] = 'p2q3r4s5t6u7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('unit_preference', sa.String(10), nullable=False, server_default='metric'))


def downgrade() -> None:
    op.drop_column('users', 'unit_preference')
