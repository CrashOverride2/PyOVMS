"""Add unique constraint to charge_log_points

Revision ID: k7l8m9n0o1p2
Revises: a0b1c2d3e4f5
Create Date: 2025-10-04 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'k7l8m9n0o1p2'
down_revision: Union[str, None] = 'a0b1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # First, remove any existing duplicate entries
    # Keep only the first occurrence based on id for each (charge_log_id_fk, timestamp) pair
    op.execute("""
        DELETE FROM charge_log_points
        WHERE id NOT IN (
            SELECT MIN(id)
            FROM charge_log_points
            GROUP BY charge_log_id_fk, timestamp
        )
    """)

    # Add unique constraint to prevent future duplicates
    with op.batch_alter_table('charge_log_points', schema=None) as batch_op:
        batch_op.create_unique_constraint(
            'uq_charge_log_points_log_timestamp',
            ['charge_log_id_fk', 'timestamp']
        )


def downgrade() -> None:
    # Remove the unique constraint
    with op.batch_alter_table('charge_log_points', schema=None) as batch_op:
        batch_op.drop_constraint('uq_charge_log_points_log_timestamp', type_='unique')
