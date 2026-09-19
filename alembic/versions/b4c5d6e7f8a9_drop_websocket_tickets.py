"""Delete the WebSocket ticket rows

A page used to fetch a one-shot API key ("ws-ticket-<user>-<ts>", valid 60 s) and
hand it to /ws, which consumed it. The socket is authenticated by the session cookie
now and the `ws-ticket-` prefix is no longer an internal one, so any row left from
the old server — a page opened and abandoned in the last hour before the upgrade —
would surface in its owner's key list and count against their quota until the
hourly sweep. None of them was ever registered with the broker, so a plain delete
is the whole cleanup.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-09-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b4c5d6e7f8a9'
down_revision: Union[str, None] = 'a3b4c5d6e7f8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    api_keys = sa.table('api_keys', sa.column('name', sa.String))
    op.execute(api_keys.delete().where(api_keys.c.name.like('ws-ticket-%')))


def downgrade() -> None:
    # The rows were 60-second credentials; there is nothing to restore.
    pass
