"""hash email verification and password reset tokens

Revision ID: c4d5e6f7a8b9
Revises: b2c3d4e5f6a7
Create Date: 2026-08-08

Both columns used to hold the raw token that was mailed to the user, so any dump of
the users table contained ready-to-use account-takeover credentials. From here on
they hold a SHA-256 hash (see app.security.hash_url_token).

There is no way to convert the existing rows: hashing them would be pointless (the
plaintext they came from is already out in the world, in mailboxes and access logs)
and leaving them would make the lookup fail in a way that silently rejects a valid
link. They are therefore cleared. The cost is that pending reset and verification
links stop working at the moment of the upgrade, which is bounded by the token
lifetime — hours, not days — and both are re-requestable from the login page. That
is the correct trade for retiring credentials whose raw form was stored.

Accounts that were awaiting email verification keep is_active=False; their owner
gets a new mail by using "resend verification". Clearing the expiry alongside the
token matters because the routes read the expiry first: a NULL token with a
lingering expiry would be an unreachable half-state.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Invalidate every stored plaintext token."""
    op.execute(
        sa.text(
            "UPDATE users SET email_verification_token = NULL, "
            "email_verification_token_expires_at = NULL "
            "WHERE email_verification_token IS NOT NULL"
        )
    )
    op.execute(
        sa.text(
            "UPDATE users SET password_reset_token = NULL, "
            "password_reset_token_expires_at = NULL "
            "WHERE password_reset_token IS NOT NULL"
        )
    )


def downgrade() -> None:
    """
    Nothing to undo.

    The column types are unchanged; only the contents were dropped, and those cannot
    be reconstructed. Downgrading leaves the columns empty, which is a valid state
    for the old code as well — it just means no reset is currently pending.
    """
    pass
