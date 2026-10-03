"""Move the last vehicle-level notification targets into push_subscriptions, drop the columns

`s5t6u7v8w9a0` and `u7v8w9a0b1c2` copied the vehicle-level targets into
`push_subscriptions` once, but the registration endpoints kept writing both and the
dispatcher kept a per-channel fallback to the vehicle columns. That fallback is what
made a target nobody could see or remove: the GUI lists subscriptions only, removing
one leaves the vehicle copy behind, and a dead legacy target has no row the dispatcher
could reap. The case that surfaced it: a phone that registered FCM once and then
switched to UnifiedPush. Its FCM subscription row was replaced, the vehicle copy of the
FCM token was not, and with no FCM subscription left the fallback sent every
notification to that token as well — twice on screen, with nothing in the GUI to say
why.

From here on a subscription is the only kind of target. What this migration keeps is
exactly what is still a live, intended target:

  * **FCM / APNs / UnifiedPush** become a `legacy` device row only on a vehicle that has
    no app-registered subscription of any of the three. Where one exists, the vehicle
    copy is the shadow of an app registration — the API wrote both on every call — and
    carrying it over would make the duplicate permanent. A V2 app re-sends its token on
    every login, and that now lands as a subscription of its own.
  * **ntfy** becomes a row when the vehicle had it enabled and has no ntfy subscription,
    with the vehicle's topic or, as the fallback did, the server's default topic.
  * **Email** likewise, for an enabled vehicle with an address and no e-mail row.

The encrypted ntfy credentials are copied as stored: both tables hold them under the
same key, in the same format.

Downgrade restores the columns, empty. The subscriptions carry every target either way,
and the older code reads them first, so nothing stops being delivered.

Revision ID: c6d7e8f9a0b1
Revises: b4c5d6e7f8a9
Create Date: 2026-10-02

"""
import datetime
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column, select, table


revision: str = 'c6d7e8f9a0b1'
down_revision: Union[str, None] = 'b4c5d6e7f8a9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_MOBILE_TYPES = ('fcm', 'apns', 'up')

_NTFY_KEYS = (
    'ntfy_server_url', 'ntfy_auth_method', 'ntfy_auth_token',
    'ntfy_auth_user', 'ntfy_auth_password', 'ntfy_auth_query_param_name',
)

# (name, type, nullable) as the columns were last defined on the model.
_LEGACY_COLUMNS = (
    ('enable_ntfy_notifications', sa.Boolean(), True),
    ('enable_email_notifications', sa.Boolean(), True),
    ('enable_fcm_notifications', sa.Boolean(), True),
    ('enable_apns_notifications', sa.Boolean(), False),
    ('enable_unified_push_notifications', sa.Boolean(), False),
    ('unified_push_endpoint', sa.String(500), True),
    ('ntfy_topic', sa.String(100), True),
    ('ntfy_server_url', sa.String(255), True),
    ('ntfy_auth_method', sa.String(50), True),
    ('ntfy_auth_token', sa.LargeBinary(), True),
    ('ntfy_auth_user', sa.String(100), True),
    ('ntfy_auth_password', sa.LargeBinary(), True),
    ('ntfy_auth_query_param_name', sa.String(50), True),
    ('notification_email', sa.String(255), True),
    ('fcm_token', sa.String(255), True),
    ('apns_token', sa.String(255), True),
)


def _default_ntfy_topic() -> str:
    # What the dispatcher fell back to for an enabled vehicle without a topic. Read
    # here rather than hard-coded, so a server that configured its own keeps it.
    try:
        from app.config import settings
        return settings.NTFY_DEFAULT_TOPIC or ''
    except Exception:
        return ''


def plan_subscriptions(row, existing_types, default_topic: str, now) -> list[dict]:
    """The subscription rows one vehicle's legacy columns turn into.

    `row` is a mapping of the vehicle's columns, `existing_types` the push types the
    vehicle already has subscriptions of. Separate from `upgrade()` so the rules can be
    read — and tested — without a migration context.
    """
    vid = row['id']
    rows = []

    def add(device_id, push_type, endpoint, **ntfy):
        # Every row carries every key. bulk_insert is one executemany, and its column
        # list is compiled from a single row: on PostgreSQL a row missing a key fails
        # the whole insert, on SQLite the first row's keys win and a later ntfy row
        # loses its server and credentials without a word.
        rows.append({
            'vehicle_id_fk': vid,
            'device_id': device_id[:255],
            'push_type': push_type,
            'endpoint': endpoint[:500],
            **{key: ntfy.get(key) for key in _NTFY_KEYS},
            'created_at': now,
            'updated_at': now,
        })

    if not existing_types.intersection(_MOBILE_TYPES):
        if row['enable_fcm_notifications'] and row['fcm_token']:
            add('legacy', 'fcm', row['fcm_token'])
        if row['enable_apns_notifications'] and row['apns_token']:
            add('legacy', 'apns', row['apns_token'])
        if row['enable_unified_push_notifications'] and row['unified_push_endpoint']:
            add('legacy', 'up', row['unified_push_endpoint'])

    if row['enable_ntfy_notifications'] and 'ntfy' not in existing_types:
        topic = (row['ntfy_topic'] or default_topic or '').strip()
        if topic:
            add(
                topic, 'ntfy', topic,
                ntfy_server_url=row['ntfy_server_url'],
                ntfy_auth_method=row['ntfy_auth_method'],
                ntfy_auth_token=row['ntfy_auth_token'],
                ntfy_auth_user=row['ntfy_auth_user'],
                ntfy_auth_password=row['ntfy_auth_password'],
                ntfy_auth_query_param_name=row['ntfy_auth_query_param_name'],
            )

    if row['enable_email_notifications'] and 'email' not in existing_types:
        address = (row['notification_email'] or '').strip()
        if address:
            add(address, 'email', address)

    return rows


def upgrade() -> None:
    vehicles = table('vehicles', column('id', sa.Integer),
                     *(column(name, type_) for name, type_, _ in _LEGACY_COLUMNS))
    push_subscriptions = table(
        'push_subscriptions',
        column('vehicle_id_fk', sa.Integer),
        column('device_id', sa.String),
        column('push_type', sa.String),
        column('endpoint', sa.String),
        column('ntfy_server_url', sa.String),
        column('ntfy_auth_method', sa.String),
        column('ntfy_auth_token', sa.LargeBinary),
        column('ntfy_auth_user', sa.String),
        column('ntfy_auth_password', sa.LargeBinary),
        column('ntfy_auth_query_param_name', sa.String),
        column('created_at', sa.DateTime(timezone=True)),
        column('updated_at', sa.DateTime(timezone=True)),
    )

    conn = op.get_bind()
    existing: dict[int, set[str]] = {}
    for vid, push_type in conn.execute(
        select(push_subscriptions.c.vehicle_id_fk, push_subscriptions.c.push_type)
    ):
        existing.setdefault(vid, set()).add(push_type)

    default_topic = _default_ntfy_topic()
    now = datetime.datetime.now(datetime.timezone.utc)
    inserts = []
    for row in conn.execute(select(vehicles)).mappings():
        inserts.extend(plan_subscriptions(row, existing.get(row['id'], set()), default_topic, now))

    if inserts:
        op.bulk_insert(push_subscriptions, inserts)

    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        for name, _type, _nullable in _LEGACY_COLUMNS:
            batch_op.drop_column(name)


def downgrade() -> None:
    with op.batch_alter_table('vehicles', schema=None) as batch_op:
        for name, type_, nullable in _LEGACY_COLUMNS:
            batch_op.add_column(sa.Column(
                name, type_, nullable=nullable,
                server_default=sa.false() if isinstance(type_, sa.Boolean) else None,
            ))
