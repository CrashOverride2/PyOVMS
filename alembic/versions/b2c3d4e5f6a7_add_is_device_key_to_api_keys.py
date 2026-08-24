"""add is_device_key to api_keys

Marks the keys issued by POST /api/v1/auth/device-token. Only those keys get the
sliding expiry (180 days from last use instead of from issue).

The flag is a column rather than something derived from the key name on purpose.
Deriving it would silently change the meaning of rows that already exist: a user who
had named a key "device-tesla" and given it a deliberate 30-day expiry would have seen
that expiry pushed out to 180 days on every request — the opposite of what they asked
for. Existing rows therefore all get False, including any that happen to be named with
the device prefix. They keep behaving exactly as before.

Note for anyone who deployed the intermediate state: keys provisioned by the app
before this migration land as False and stop sliding. Opening the app re-provisions
the device and the replacement key carries the flag.

Revision ID: b2c3d4e5f6a7
Revises: 1da1800e95c7
Create Date: 2026-08-02

"""
from alembic import op
import sqlalchemy as sa


revision = 'b2c3d4e5f6a7'
down_revision = '1da1800e95c7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('api_keys') as batch_op:
        batch_op.add_column(
            sa.Column(
                'is_device_key',
                sa.Boolean(),
                nullable=False,
                # server_default so the NOT NULL constraint can be satisfied for rows
                # that already exist. sa.false() renders per backend (0 on SQLite and
                # MySQL, false on PostgreSQL).
                server_default=sa.false(),
            )
        )


def downgrade() -> None:
    with op.batch_alter_table('api_keys') as batch_op:
        batch_op.drop_column('is_device_key')
