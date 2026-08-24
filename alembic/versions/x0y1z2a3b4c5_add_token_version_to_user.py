"""Add token_version to users for JWT revocation on password change

Revision ID: x0y1z2a3b4c5
Revises: w9a0b1c2d3e4
Create Date: 2026-06-01 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'x0y1z2a3b4c5'
down_revision: Union[str, None] = 'w9a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('users', sa.Column('token_version', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    op.drop_column('users', 'token_version')
