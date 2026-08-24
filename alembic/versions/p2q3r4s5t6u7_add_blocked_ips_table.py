"""Add blocked_ips table for persistent rate limiting

Revision ID: p2q3r4s5t6u7
Revises: o1p2q3r4s5t6
Create Date: 2026-02-27 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'p2q3r4s5t6u7'
down_revision: Union[str, None] = 'o1p2q3r4s5t6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'blocked_ips',
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('unblock_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reason', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('ip'),
    )
    op.create_index('ix_blocked_ips_unblock_at', 'blocked_ips', ['unblock_at'])


def downgrade() -> None:
    op.drop_index('ix_blocked_ips_unblock_at', table_name='blocked_ips')
    op.drop_table('blocked_ips')
