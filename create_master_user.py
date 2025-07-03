import os
from app import app, db, Usuario

with app.app_context():
    if not Usuario.query.filter_by(username='mcontreras').first():
        master = Usuario(
            username='mcontreras',
            nombre='Mauro',
            apellidos='Contreras Palma',
            correo='mauro.contreraspalma@gmail.com',
            comision='',
            rol='master'
        )
        master.password = 'Program3312' # Considera usar una variable de entorno para esta contraseña en producción
        db.session.add(master)
        db.session.commit()
        print("Usuario 'mcontreras' creado exitosamente.")
    else:
        print("El usuario 'mcontreras' ya existe.")
