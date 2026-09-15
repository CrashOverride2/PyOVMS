"""Add command_favorites table

Saved terminal commands, owned by a user — not by a vehicle, so a favorite shows
up in the terminal of every vehicle its owner can command. The row holds the raw
command text as the user typed it (no V2 `7,` prefix; the terminal adds that at
send time), a short label for the button, and a position for stable ordering.

Revision ID: a3b4c5d6e7f8
Revises: z2a3b4c5d6e7
Create Date: 2026-09-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a3b4c5d6e7f8'
down_revision: Union[str, None] = 'z2a3b4c5d6e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'command_favorites',
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('owner_id', sa.Integer(),
                  sa.ForeignKey('users.id', name='fk_commandfavorite_owner_id', ondelete='CASCADE'),
                  nullable=False, index=True),
        sa.Column('label', sa.String(40), nullable=False),
        sa.Column('command', sa.String(200), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index(
        'ix_command_favorites_owner_position', 'command_favorites',
        ['owner_id', 'position'],
    )


def downgrade() -> None:
    op.drop_index('ix_command_favorites_owner_position', table_name='command_favorites')
    op.drop_table('command_favorites')
