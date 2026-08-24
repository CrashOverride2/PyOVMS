"""add missing security columns to users

Revision ID: f29293b2cdd9
Revises: 3af4188864dd
Create Date: 2025-10-06 13:07:58.159553

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = 'f29293b2cdd9'
down_revision: Union[str, None] = '3af4188864dd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check existing columns in users table
    existing_columns = [col['name'] for col in inspector.get_columns('users')]

    # Add missing columns to users table
    columns_to_add = []
    if 'totp_key_version' not in existing_columns:
        columns_to_add.append(sa.Column('totp_key_version', sa.Integer(), nullable=True))
    if 'webauthn_enabled' not in existing_columns:
        columns_to_add.append(sa.Column('webauthn_enabled', sa.Boolean(), nullable=False, server_default='0'))

    if columns_to_add:
        with op.batch_alter_table('users', schema=None) as batch_op:
            for col in columns_to_add:
                batch_op.add_column(col)

    # Check if webauthn_credentials table exists
    existing_tables = inspector.get_table_names()

    if 'webauthn_credentials' not in existing_tables:
        # Create webauthn_credentials table
        op.create_table('webauthn_credentials',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('credential_id', sa.String(length=255), nullable=False),
            sa.Column('public_key', sa.Text(), nullable=False),
            sa.Column('sign_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('credential_name', sa.String(length=100), nullable=True),
            sa.Column('credential_type', sa.String(length=50), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_webauthn_user_id'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_webauthn_credentials_id'), 'webauthn_credentials', ['id'], unique=False)
        op.create_index(op.f('ix_webauthn_credentials_credential_id'), 'webauthn_credentials', ['credential_id'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    # Drop webauthn_credentials table
    op.drop_index(op.f('ix_webauthn_credentials_credential_id'), table_name='webauthn_credentials')
    op.drop_index(op.f('ix_webauthn_credentials_id'), table_name='webauthn_credentials')
    op.drop_table('webauthn_credentials')

    # Drop columns from users table
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('webauthn_enabled')
        batch_op.drop_column('totp_key_version')
