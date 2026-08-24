"""add is_discoverable to webauthn_credentials

Records whether an authenticator stored a passwordless credential on itself (a
"resident key"), so the passwordless login can stop naming every credential it knows.

POST /webauthn/auth/begin used to answer with an allowCredentials list containing
*every* passwordless credential on the server. The endpoint needs no authentication
beyond a CSRF token that the login page hands to anyone, so a single request returned
the credential id of every passkey user. It did that because registration never asked
for a resident key: a credential that is not discoverable cannot be found by the
authenticator on its own and must be named, or the user simply cannot sign in.

Registration now requests resident keys for passwordless credentials and records the
credProps.rk result here. New credentials are discoverable and no longer have to be
named; the login only names the ones that still have to be.

Existing rows get NULL, meaning "registered before we asked". NULL and False are both
treated as "must be named", which keeps every current passkey working. The alternative —
assuming they are discoverable — would lock out exactly those accounts that have a
passwordless key and no second factor, because those cannot log in by password either
(see app/utils/two_factor.password_login_is_disabled). Those rows disappear as their
owners re-register, and the disclosure shrinks with them.

Nullable on purpose rather than NOT NULL with a default: "we never asked" and "the
authenticator told us no" are different facts, and only the first one is worth
prompting a user to re-register over.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-08-08

"""
from alembic import op
import sqlalchemy as sa


revision = 'e6f7a8b9c0d1'
down_revision = 'd5e6f7a8b9c0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('webauthn_credentials') as batch_op:
        batch_op.add_column(
            sa.Column('is_discoverable', sa.Boolean(), nullable=True)
        )


def downgrade() -> None:
    with op.batch_alter_table('webauthn_credentials') as batch_op:
        batch_op.drop_column('is_discoverable')
