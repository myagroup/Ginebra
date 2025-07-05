"""Cambiar fecha_venta a tipo Date

Revision ID: 43f103b668df
Revises: 1252d2766698
Create Date: 2025-07-04 23:02:57.099239

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column
from sqlalchemy import String, Date
from datetime import datetime


# revision identifiers, used by Alembic.
revision = '43f103b668df'
down_revision = '1252d2766698'
branch_labels = None
depends_on = None


def upgrade():
    # Eliminar columna temporal si ya existe (por migración fallida previa)
    conn = op.get_bind()
    insp = sa.inspect(conn)
    columns = [col['name'] for col in insp.get_columns('reserva')]
    if 'fecha_venta_tmp' in columns:
        with op.batch_alter_table('reserva') as batch_op:
            batch_op.drop_column('fecha_venta_tmp')

    # 1. Crear columna temporal
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.add_column(sa.Column('fecha_venta_tmp', sa.Date(), nullable=True))

    # 2. Copiar y convertir datos existentes
    reserva_table = table('reserva',
        column('id', sa.Integer),
        column('fecha_venta', String),
        column('fecha_venta_tmp', Date)
    )
    results = conn.execute(sa.select(reserva_table.c.id, reserva_table.c.fecha_venta)).fetchall()
    for row in results:
        fecha_str = row.fecha_venta
        fecha_date = None
        if fecha_str:
            for fmt in ('%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y', '%Y/%m/%d'):
                try:
                    fecha_date = datetime.strptime(fecha_str, fmt).date()
                    break
                except Exception:
                    continue
        conn.execute(
            reserva_table.update().where(reserva_table.c.id == row.id).values(fecha_venta_tmp=fecha_date)
        )

    # 3. Eliminar columna original
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.drop_column('fecha_venta')

    # 4. Renombrar columna temporal
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.alter_column('fecha_venta_tmp', new_column_name='fecha_venta')

def downgrade():
    # Downgrade: revertir el proceso
    conn = op.get_bind()
    insp = sa.inspect(conn)
    columns = [col['name'] for col in insp.get_columns('reserva')]
    if 'fecha_venta_tmp' in columns:
        with op.batch_alter_table('reserva') as batch_op:
            batch_op.drop_column('fecha_venta_tmp')
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.add_column(sa.Column('fecha_venta_tmp', sa.String(50), nullable=True))
    reserva_table = table('reserva',
        column('id', sa.Integer),
        column('fecha_venta', Date),
        column('fecha_venta_tmp', String)
    )
    results = conn.execute(sa.select(reserva_table.c.id, reserva_table.c.fecha_venta)).fetchall()
    for row in results:
        fecha_date = row.fecha_venta
        fecha_str = fecha_date.strftime('%Y-%m-%d') if fecha_date else None
        conn.execute(
            reserva_table.update().where(reserva_table.c.id == row.id).values(fecha_venta_tmp=fecha_str)
        )
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.drop_column('fecha_venta')
    with op.batch_alter_table('reserva') as batch_op:
        batch_op.alter_column('fecha_venta_tmp', new_column_name='fecha_venta')
