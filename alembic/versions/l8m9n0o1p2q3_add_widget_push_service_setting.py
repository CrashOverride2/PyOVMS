"""Add widget push service system setting

Revision ID: l8m9n0o1p2q3
Revises: d56971878f39
Create Date: 2025-10-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'l8m9n0o1p2q3'
down_revision: Union[str, None] = 'd56971878f39'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Insert the default setting for widget push service (enabled by default)
    op.execute("""
        INSERT INTO system_settings (key, value, updated_at)
        SELECT 'ENABLE_WIDGET_PUSH_SERVICE', 'true', CURRENT_TIMESTAMP
        WHERE NOT EXISTS (
            SELECT 1 FROM system_settings WHERE key = 'ENABLE_WIDGET_PUSH_SERVICE'
        )
    """)


def downgrade() -> None:
    # Remove the widget push service setting
    op.execute("""
        DELETE FROM system_settings WHERE key = 'ENABLE_WIDGET_PUSH_SERVICE'
    """)
