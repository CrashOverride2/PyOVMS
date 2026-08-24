"""add usage_mode to webauthn_credentials

Revision ID: 756aafc64c77
Revises: f29293b2cdd9
Create Date: 2025-10-06 13:26:45.059411

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '756aafc64c77'
down_revision: Union[str, None] = 'f29293b2cdd9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()
    from sqlalchemy import inspect
    inspector = inspect(conn)

    # Check if webauthn_credentials table exists
    existing_tables = inspector.get_table_names()

    if 'webauthn_credentials' in existing_tables:
        # Check existing columns
        existing_columns = [col['name'] for col in inspector.get_columns('webauthn_credentials')]

        if 'usage_mode' not in existing_columns:
            with op.batch_alter_table('webauthn_credentials', schema=None) as batch_op:
                batch_op.add_column(sa.Column('usage_mode', sa.String(length=20), nullable=False, server_default='passwordless'))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('webauthn_credentials', schema=None) as batch_op:
        batch_op.drop_column('usage_mode')
