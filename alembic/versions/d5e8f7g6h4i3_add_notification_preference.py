"""add notification preference

Revision ID: d5e8f7g6h4i3
Revises: b3d4c5a6e7f8
Create Date: 2025-07-12 01:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e8f7g6h4i3'
down_revision: Union[str, None] = 'b3d4c5a6e7f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('notification_preference', sa.String(length=10), nullable=True, server_default='v3'))


def downgrade() -> None:
    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        batch_op.drop_column('notification_preference')