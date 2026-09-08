"""security_events.user_id FK: ON DELETE SET NULL

An account that had ever produced a security event could not be deleted at all on
PostgreSQL/MySQL: `security_events` is the only table referencing `users.id` without an
ORM relationship, so nothing in the unit of work cleared it and the DELETE hit
fk_security_event_user_id. SET NULL rather than CASCADE — the audit trail is the record
of what the account did and has to outlive it; the `username` column keeps the row
readable once the id is gone.

Revision ID: y1z2a3b4c5d6
Revises: e6f7a8b9c0d1
Create Date: 2026-09-06

"""
from typing import Sequence, Union

from alembic import op

revision: str = 'y1z2a3b4c5d6'
down_revision: Union[str, None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CONSTRAINT = "fk_security_event_user_id"


def upgrade() -> None:
    # batch mode so SQLite (which cannot ALTER a constraint) is rebuilt instead.
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.drop_constraint(CONSTRAINT, type_="foreignkey")
        batch_op.create_foreign_key(
            CONSTRAINT, "users", ["user_id"], ["id"], ondelete="SET NULL"
        )


def downgrade() -> None:
    with op.batch_alter_table("security_events") as batch_op:
        batch_op.drop_constraint(CONSTRAINT, type_="foreignkey")
        batch_op.create_foreign_key(CONSTRAINT, "users", ["user_id"], ["id"])
