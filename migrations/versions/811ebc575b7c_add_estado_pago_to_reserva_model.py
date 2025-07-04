"""Add estado_pago to Reserva model

Revision ID: 811ebc575b7c
Revises: 3951959bf3fe
Create Date: 2025-07-04 15:11:22.990176

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '811ebc575b7c'
down_revision = '3951959bf3fe'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('reserva', schema=None) as batch_op:
        batch_op.add_column(sa.Column('estado_pago', sa.String(length=50), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('reserva', schema=None) as batch_op:
        batch_op.drop_column('estado_pago')

    # ### end Alembic commands ###
