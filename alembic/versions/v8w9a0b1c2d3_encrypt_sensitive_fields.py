"""Encrypt sensitive fields: paranoid_token, ntfy_auth_token/password, AP passwords

Revision ID: v8w9a0b1c2d3
Revises: u7v8w9a0b1c2
Create Date: 2026-05-31 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision: str = 'v8w9a0b1c2d3'
down_revision: Union[str, None] = 'u7v8w9a0b1c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _get_encrypt():
    """Import encrypt_data lazily so settings are loaded before use."""
    from app.utils.crypto import encrypt_data
    return encrypt_data


def upgrade() -> None:
    conn = op.get_bind()
    encrypt_data = _get_encrypt()

    # ------------------------------------------------------------------ #
    # 1. Read all existing plaintext values before altering column types   #
    # ------------------------------------------------------------------ #
    vehicle_rows = conn.execute(text(
        "SELECT id, paranoid_token, ntfy_auth_token, ntfy_auth_password FROM vehicles"
    )).fetchall()

    ap_rows = conn.execute(text(
        "SELECT id, target_server_password, target_module_password FROM auto_provision_profiles"
    )).fetchall()

    ps_rows = conn.execute(text(
        "SELECT id, ntfy_auth_token, ntfy_auth_password FROM push_subscriptions"
    )).fetchall()

    # ------------------------------------------------------------------ #
    # 2. Alter column types to LargeBinary                                 #
    # ------------------------------------------------------------------ #
    dialect = conn.dialect.name

    if dialect == 'postgresql':
        # PostgreSQL requires explicit USING cast for VARCHAR -> BYTEA
        conn.execute(text("ALTER TABLE vehicles ALTER COLUMN paranoid_token TYPE BYTEA USING paranoid_token::bytea"))
        conn.execute(text("ALTER TABLE vehicles ALTER COLUMN ntfy_auth_token TYPE BYTEA USING ntfy_auth_token::bytea"))
        conn.execute(text("ALTER TABLE vehicles ALTER COLUMN ntfy_auth_password TYPE BYTEA USING ntfy_auth_password::bytea"))
        conn.execute(text("ALTER TABLE auto_provision_profiles ALTER COLUMN target_server_password TYPE BYTEA USING target_server_password::bytea"))
        conn.execute(text("ALTER TABLE auto_provision_profiles ALTER COLUMN target_module_password TYPE BYTEA USING target_module_password::bytea"))
        conn.execute(text("ALTER TABLE push_subscriptions ALTER COLUMN ntfy_auth_token TYPE BYTEA USING ntfy_auth_token::bytea"))
        conn.execute(text("ALTER TABLE push_subscriptions ALTER COLUMN ntfy_auth_password TYPE BYTEA USING ntfy_auth_password::bytea"))
    else:
        with op.batch_alter_table('vehicles') as batch_op:
            batch_op.alter_column('paranoid_token',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(64),
                                  existing_nullable=True)
            batch_op.alter_column('ntfy_auth_token',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(255),
                                  existing_nullable=True)
            batch_op.alter_column('ntfy_auth_password',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(100),
                                  existing_nullable=True)

        with op.batch_alter_table('auto_provision_profiles') as batch_op:
            batch_op.alter_column('target_server_password',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(32),
                                  existing_nullable=False)
            batch_op.alter_column('target_module_password',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(32),
                                  existing_nullable=True)

        with op.batch_alter_table('push_subscriptions') as batch_op:
            batch_op.alter_column('ntfy_auth_token',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(255),
                                  existing_nullable=True)
            batch_op.alter_column('ntfy_auth_password',
                                  type_=sa.LargeBinary(),
                                  existing_type=sa.String(100),
                                  existing_nullable=True)

    # ------------------------------------------------------------------ #
    # 3. Write back Fernet-encrypted values                                #
    # ------------------------------------------------------------------ #
    for row in vehicle_rows:
        updates = {}
        # row columns: id, paranoid_token, ntfy_auth_token, ntfy_auth_password
        if row[1]:
            updates['paranoid_token'] = encrypt_data(row[1]) if isinstance(row[1], str) else row[1]
        if row[2]:
            updates['ntfy_auth_token'] = encrypt_data(row[2]) if isinstance(row[2], str) else row[2]
        if row[3]:
            updates['ntfy_auth_password'] = encrypt_data(row[3]) if isinstance(row[3], str) else row[3]
        if updates:
            set_parts = ', '.join(f"{k} = :{k}" for k in updates)
            conn.execute(text(f"UPDATE vehicles SET {set_parts} WHERE id = :_id"),
                         {**updates, '_id': row[0]})

    for row in ap_rows:
        # row columns: id, target_server_password, target_module_password
        updates = {}
        if row[1]:
            updates['target_server_password'] = encrypt_data(row[1]) if isinstance(row[1], str) else row[1]
        if row[2]:
            updates['target_module_password'] = encrypt_data(row[2]) if isinstance(row[2], str) else row[2]
        if updates:
            set_parts = ', '.join(f"{k} = :{k}" for k in updates)
            conn.execute(text(f"UPDATE auto_provision_profiles SET {set_parts} WHERE id = :_id"),
                         {**updates, '_id': row[0]})

    for row in ps_rows:
        # row columns: id, ntfy_auth_token, ntfy_auth_password
        updates = {}
        if row[1]:
            updates['ntfy_auth_token'] = encrypt_data(row[1]) if isinstance(row[1], str) else row[1]
        if row[2]:
            updates['ntfy_auth_password'] = encrypt_data(row[2]) if isinstance(row[2], str) else row[2]
        if updates:
            set_parts = ', '.join(f"{k} = :{k}" for k in updates)
            conn.execute(text(f"UPDATE push_subscriptions SET {set_parts} WHERE id = :_id"),
                         {**updates, '_id': row[0]})


def downgrade() -> None:
    # Downgrade intentionally does NOT decrypt — column types are reverted to String
    # but existing data remains as encrypted bytes (unreadable as plain text).
    with op.batch_alter_table('push_subscriptions') as batch_op:
        batch_op.alter_column('ntfy_auth_password',
                              type_=sa.String(100),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)
        batch_op.alter_column('ntfy_auth_token',
                              type_=sa.String(255),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)

    with op.batch_alter_table('auto_provision_profiles') as batch_op:
        batch_op.alter_column('target_module_password',
                              type_=sa.String(32),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)
        batch_op.alter_column('target_server_password',
                              type_=sa.String(32),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=False)

    with op.batch_alter_table('vehicles') as batch_op:
        batch_op.alter_column('ntfy_auth_password',
                              type_=sa.String(100),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)
        batch_op.alter_column('ntfy_auth_token',
                              type_=sa.String(255),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)
        batch_op.alter_column('paranoid_token',
                              type_=sa.String(64),
                              existing_type=sa.LargeBinary(),
                              existing_nullable=True)
