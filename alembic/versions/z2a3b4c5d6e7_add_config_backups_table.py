"""Add config_backups table

Snapshots of the OVMS Connect app's configuration, one row per snapshot, owned by
a user. The payload is JSON text — no credentials, no images — so a single table
with the document in a Text column is the whole storage model; `with_variant`
gives MySQL a LONGTEXT because its TEXT stops at 64 KiB.

Revision ID: z2a3b4c5d6e7
Revises: y1z2a3b4c5d6
Create Date: 2026-09-11

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.mysql import LONGTEXT


revision: str = 'z2a3b4c5d6e7'
down_revision: Union[str, None] = 'y1z2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'config_backups',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('owner_id', sa.Integer(),
                  sa.ForeignKey('users.id', name='fk_configbackup_owner_id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('kind', sa.String(10), nullable=False),
        sa.Column('label', sa.String(100), nullable=True),
        sa.Column('device_id', sa.String(32), nullable=True),
        sa.Column('device_name', sa.String(64), nullable=True),
        sa.Column('app_version', sa.String(32), nullable=True),
        sa.Column('platform', sa.String(16), nullable=True),
        sa.Column('schema_version', sa.Integer(), nullable=False),
        sa.Column('payload', sa.Text().with_variant(LONGTEXT(), 'mysql'), nullable=False),
        sa.Column('stored_chars', sa.Integer(), nullable=False),
        sa.Column('payload_sha256', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index(
        'ix_config_backups_owner_kind_device_created', 'config_backups',
        ['owner_id', 'kind', 'device_id', 'created_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_config_backups_owner_kind_device_created', table_name='config_backups')
    op.drop_table('config_backups')
