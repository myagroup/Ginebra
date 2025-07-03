from app import app, db
from flask_migrate import Migrate
from flask.cli import with_appcontext
import click

migrate = Migrate(app, db)

@app.cli.command("create-db")
@with_appcontext
def create_db():
    """Crea las tablas en la base de datos."""
    db.create_all()
    click.echo("Base de datos creada.")