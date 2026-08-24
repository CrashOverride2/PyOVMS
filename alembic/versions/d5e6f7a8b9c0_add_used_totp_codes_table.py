"""add used_totp_codes table and a username rate-limit index

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-08-08

Two changes, both of which move a correctness property that used to hold only for a
single worker process into the database:

* `used_totp_codes` replaces the in-process dictionary that stopped a TOTP code from
  being used twice inside its ~90 s validity window. The unique index is what does
  the work: the insert is the check.
* The composite index on `security_failures` makes the per-username failure count
  cheap enough to run on the login path, which is what lets the distributed
  brute-force counter read from the database instead of from process memory.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd5e6f7a8b9c0'
down_revision: Union[str, None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'used_totp_codes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('code_key', sa.String(length=64), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_used_totp_codes_id'), 'used_totp_codes', ['id'], unique=False)
    op.create_index(op.f('ix_used_totp_codes_code_key'), 'used_totp_codes', ['code_key'], unique=True)
    op.create_index(op.f('ix_used_totp_codes_used_at'), 'used_totp_codes', ['used_at'], unique=False)

    # The per-username counter filters on all three columns at once; the existing
    # single-column indexes would each match a large slice of the table.
    op.create_index(
        'ix_security_failures_username_type_time',
        'security_failures',
        ['username', 'auth_type', 'created_at'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index('ix_security_failures_username_type_time', table_name='security_failures')
    op.drop_index(op.f('ix_used_totp_codes_used_at'), table_name='used_totp_codes')
    op.drop_index(op.f('ix_used_totp_codes_code_key'), table_name='used_totp_codes')
    op.drop_index(op.f('ix_used_totp_codes_id'), table_name='used_totp_codes')
    op.drop_table('used_totp_codes')
