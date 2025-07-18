"""Agregada columna comprobante_pdf a Reserva

Revision ID: 6e30718852da
Revises: b03f18dc1f3f
Create Date: 2025-07-05 22:36:20.704220

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6e30718852da'
down_revision = 'b03f18dc1f3f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('reserva', schema=None) as batch_op:
        batch_op.add_column(sa.Column('comprobante_pdf', sa.LargeBinary(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('reserva', schema=None) as batch_op:
        batch_op.drop_column('comprobante_pdf')

    # ### end Alembic commands ###
