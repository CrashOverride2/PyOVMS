"""Add lifecycle management fields for inactive vehicle/account handling

Revision ID: t6u7v8w9a0b1
Revises: s5t6u7v8w9a0
Create Date: 2026-05-23 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 't6u7v8w9a0b1'
down_revision: Union[str, None] = 's5t6u7v8w9a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('vehicles', sa.Column('unused_reminder_sent_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('account_deletion_reminder_sent_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('vehicles', 'unused_reminder_sent_at')
    op.drop_column('users', 'last_login_at')
    op.drop_column('users', 'account_deletion_reminder_sent_at')
