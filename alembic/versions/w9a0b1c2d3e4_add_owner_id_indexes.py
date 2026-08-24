"""Add indexes on vehicles.owner_id and auto_provision_profiles.owner_id

Revision ID: w9a0b1c2d3e4
Revises: v8w9a0b1c2d3
Create Date: 2026-06-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


revision: str = 'w9a0b1c2d3e4'
down_revision: Union[str, None] = 'v8w9a0b1c2d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index('ix_vehicles_owner_id', 'vehicles', ['owner_id'])
    op.create_index('ix_auto_provision_profiles_owner_id', 'auto_provision_profiles', ['owner_id'])


def downgrade() -> None:
    op.drop_index('ix_auto_provision_profiles_owner_id', table_name='auto_provision_profiles')
    op.drop_index('ix_vehicles_owner_id', table_name='vehicles')
