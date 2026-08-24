"""add_security_failures_table

Revision ID: 1da1800e95c7
Revises: x0y1z2a3b4c5
Create Date: 2026-06-01 22:34:27.968981

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1da1800e95c7'
down_revision: Union[str, None] = 'x0y1z2a3b4c5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('security_failures',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('auth_type', sa.String(length=20), nullable=False),
    sa.Column('username', sa.String(length=50), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_failures_auth_type'), 'security_failures', ['auth_type'], unique=False)
    op.create_index(op.f('ix_security_failures_created_at'), 'security_failures', ['created_at'], unique=False)
    op.create_index(op.f('ix_security_failures_id'), 'security_failures', ['id'], unique=False)
    op.create_index(op.f('ix_security_failures_ip_address'), 'security_failures', ['ip_address'], unique=False)
    op.create_index(op.f('ix_security_failures_username'), 'security_failures', ['username'], unique=False)
    
    # Correcting missing index from previous migration
    op.create_index(op.f('ix_push_subscriptions_id'), 'push_subscriptions', ['id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_push_subscriptions_id'), table_name='push_subscriptions')
    op.drop_index(op.f('ix_security_failures_username'), table_name='security_failures')
    op.drop_index(op.f('ix_security_failures_ip_address'), table_name='security_failures')
    op.drop_index(op.f('ix_security_failures_id'), table_name='security_failures')
    op.drop_index(op.f('ix_security_failures_created_at'), table_name='security_failures')
    op.drop_index(op.f('ix_security_failures_auth_type'), table_name='security_failures')
    op.drop_table('security_failures')
