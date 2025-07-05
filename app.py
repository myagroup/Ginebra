# File: app.py
import os
import io
import random
import string
from datetime import datetime, timedelta
from flask import ( Flask, render_template, redirect, url_for, request, flash, send_file, send_from_directory)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_sqlalchemy import SQLAlchemy
from flask_login import ( LoginManager, UserMixin, login_user, login_required, logout_user, current_user)
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'clave_secreta_segura')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///' + os.path.join(basedir, 'usuarios.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'comprobantes')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.example.com'  # Cambia esto por tu servidor SMTP
app.config['MAIL_PORT'] = 587  # Puerto SMTP
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@example.com'  # Cambia esto por tu correo electrónico
app.config['MAIL_PASSWORD'] = 'your-email-password'  # Cambia esto por tu contraseña de correo electrónico

mail = Mail(app)

# Configuración de itsdangerous
serializer = URLSafeTimedSerializer(app.secret_key)

# New constants for file validation
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
PER_PAGE = 10 # Constante para el número de elementos por página

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ===== MODELOS =====

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    nombre = db.Column(db.String(150))
    apellidos = db.Column(db.String(150))
    correo = db.Column(db.String(150))
    comision = db.Column(db.String(100))
    rol = db.Column(db.String(50))

    @property
    def password(self):
        raise AttributeError('No se puede leer la contraseña')

    @password.setter
    def password(self, password_plain):
        self.password_hash = generate_password_hash(password_plain)

    def check_password(self, password_plain):
        return check_password_hash(self.password_hash, password_plain)

class Reserva(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    id_localizador = db.Column(db.String(100), unique=True, nullable=False)
    fecha_viaje = db.Column(db.String(50))
    producto = db.Column(db.String(100))
    fecha_venta = db.Column(db.String(50))
    modalidad_pago = db.Column(db.String(50))
    nombre_pasajero = db.Column(db.String(100))
    telefono_pasajero = db.Column(db.String(50))
    mail_pasajero = db.Column(db.String(100))
    precio_venta_total = db.Column(db.Float, default=0.0)
    hotel_neto = db.Column(db.Float, default=0.0)
    vuelo_neto = db.Column(db.Float, default=0.0)
    traslado_neto = db.Column(db.Float, default=0.0)
    seguro_neto = db.Column(db.Float, default=0.0)
    circuito_neto = db.Column(db.Float, default=0.0)
    crucero_neto = db.Column(db.Float, default=0.0)
    excursion_neto = db.Column(db.Float, default=0.0)
    paquete_neto = db.Column(db.Float, default=0.0)
    localizadores = db.Column(db.String(200))
    nombre_ejecutivo = db.Column(db.String(100))
    correo_ejecutivo = db.Column(db.String(100))
    destino = db.Column(db.String(100))
    comprobante_venta = db.Column(db.String(200))
    estado_pago = db.Column(db.String(50), default='No Pagado') # Nuevo campo
    venta_cobrada = db.Column(db.String(50), default='No cobrada') # Nuevo campo
    venta_emitida = db.Column(db.String(50), default='No emitida') # Nuevo campo

    usuario = db.relationship('Usuario', backref=db.backref('reservas', lazy=True))


# ===== LOGIN MANAGER =====

@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


# ===== DECORADORES =====

def rol_required(*roles):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.rol not in roles:
                flash('Acceso denegado.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ===== FUNCIONES AUXILIARES =====

def puede_editar_reserva(reserva):
    return current_user.rol in ('admin', 'master') or reserva.usuario_id == current_user.id

def puede_eliminar_usuario(usuario):
    if usuario.username == 'mcontreras':
        return False
    if usuario.rol in ('admin', 'master') and current_user.rol != 'master':
        return False
    return True

def crear_usuario_master():
    if not Usuario.query.filter_by(username='mcontreras').first():
        master = Usuario(
            username='mcontreras',
            nombre='Mauro',
            apellidos='Contreras Palma',
            correo='mauro.contreraspalma@gmail.com',
            comision='',
            rol='master'
        )
        master.password = 'Program3312'
        db.session.add(master)
        db.session.commit()

def generar_localizador_unico():
    while True:
        codigo_list = random.choices(string.ascii_letters, k=8) + random.choices(string.digits, k=4)
        random.shuffle(codigo_list)
        codigo = "".join(codigo_list)
        if not Reserva.query.filter_by(id_localizador=codigo).first():
            return codigo

def _get_date_range(rango_fechas_str):
    today = datetime.now()
    if rango_fechas_str == 'ultimos_30_dias':
        start_date = today - timedelta(days=30)
        end_date = today
    else:
        try:
            # Expected format: "Month Year" (e.g., "Enero 2024")
            # Need to convert month name to number
            month_name, year_str = rango_fechas_str.split(' ')
            month_num = datetime.strptime(month_name, '%B').month # Assumes month names are in locale
            year = int(year_str)
            start_date = datetime(year, month_num, 1)
            # Calculate end of month
            if month_num == 12:
                end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
            else:
                end_date = datetime(year, month_num + 1, 1) - timedelta(days=1)
        except Exception:
            # Fallback to last 30 days if parsing fails
            start_date = today - timedelta(days=30)
            end_date = today
    return start_date, end_date

def set_reserva_fields(reserva, form):
    campos_float = [
        'precio_venta_total', 'hotel_neto', 'vuelo_neto', 'traslado_neto', 'paquete_neto',
        'seguro_neto', 'circuito_neto', 'crucero_neto', 'excursion_neto'
    ]
    campos_str = [
        'fecha_viaje', 'producto', 'fecha_venta', 'modalidad_pago',
        'nombre_pasajero', 'telefono_pasajero', 'mail_pasajero',
        'localizadores', 'nombre_ejecutivo', 'correo_ejecutivo', 'destino',
        'estado_pago', 'venta_cobrada', 'venta_emitida'  # Agregados los nuevos campos
    ]

    for campo in campos_float:
        try:
            valor = float(form.get(campo, 0) or 0)
        except (ValueError, TypeError):
            valor = 0.0
        setattr(reserva, campo, valor)

    for campo in campos_str:
        setattr(reserva, campo, form.get(campo, '').strip())

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def guardar_comprobante(file, id_localizador):
    if file and file.filename:
        if not allowed_file(file.filename):
            return None, "Tipo de archivo no permitido. Solo se aceptan PDFs."
        
        # Check file size before saving
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0) # Reset file pointer to the beginning

        if file_size > MAX_CONTENT_LENGTH:
            return None, f"El archivo es demasiado grande. El tamaño máximo permitido es {MAX_CONTENT_LENGTH / (1024 * 1024):.0f} MB."

        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        nombre_final = f"{id_localizador}_{timestamp}_{filename}"
        ruta = os.path.join(app.config['UPLOAD_FOLDER'], nombre_final)
        file.save(ruta)
        return nombre_final, None
    return None, None


# ===== RUTAS =====


@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = Usuario.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Usuario o contraseña incorrectos.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', nombre=current_user.nombre)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión correctamente.', 'info')
    return redirect(url_for('login'))



@app.route('/admin')
@login_required
@rol_required('admin', 'master')
def admin_panel():
    usuarios = Usuario.query.all() if current_user.rol == 'master' else Usuario.query.filter(Usuario.username != 'mcontreras').all()
    return render_template('admin_panel.html', usuarios=usuarios)

@app.route('/admin/reservas')
@login_required
@rol_required('admin', 'master')
def admin_reservas():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)

    reservas_query = Reserva.query

    if search_query:
        reservas_query = reservas_query.filter(
            db.or_(
                Reserva.id_localizador.ilike(f'%{search_query}%'),
                Reserva.producto.ilike(f'%{search_query}%'),
                Reserva.nombre_pasajero.ilike(f'%{search_query}%'),
                Reserva.destino.ilike(f'%{search_query}%'),
                Reserva.nombre_ejecutivo.ilike(f'%{search_query}%'),
                Reserva.usuario.has(Usuario.username.ilike(f'%{search_query}%')) # Search by username
            )
        )

    reservas_paginated = reservas_query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    reservas = reservas_paginated.items
    return render_template('admin_reservas.html', reservas=reservas, pagination=reservas_paginated, search_query=search_query)

@app.route('/admin/usuarios/nuevo', methods=['GET', 'POST'])
@login_required
@rol_required('admin', 'master')
def nuevo_usuario():
    if request.method == 'POST':
        username = request.form['username'].strip()
        rol_nuevo_usuario = request.form['rol'].strip()

    # Validación de permisos según rol actual
        if current_user.rol == 'admin' and rol_nuevo_usuario != 'usuario':
            flash("No tienes permiso para crear usuarios con ese rol.", "danger")
            return redirect(url_for('nuevo_usuario'))
        elif current_user.rol == 'usuario':
            flash("No tienes permiso para crear usuarios.", "danger")
            return redirect(url_for('nuevo_usuario'))
    # master puede crear cualquier rol

        if Usuario.query.filter_by(username=username).first():
            flash('El usuario ya existe.', 'warning')
            return redirect(url_for('nuevo_usuario'))

        nuevo = Usuario(
            username=username,
            nombre=request.form['nombre'].strip(),
            apellidos=request.form['apellidos'].strip(),
            correo=request.form['correo'].strip(),
            comision=request.form['comision'].strip(),
            rol=rol_nuevo_usuario
        )
        nuevo.password = request.form['password'].strip()
        db.session.add(nuevo)
        db.session.commit()
        flash('Usuario creado correctamente.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('nuevo_usuario.html')

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@rol_required('admin', 'master')
def editar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if usuario.username == 'mcontreras' and current_user.rol != 'master':
        flash('No puedes editar al usuario master.', 'danger')
        return redirect(url_for('admin_panel'))
    if usuario.rol in ('admin', 'master') and current_user.rol != 'master':
        flash('Solo el master puede editar usuarios administradores.', 'danger')
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        usuario.username = request.form['username'].strip()
        password = request.form['password'].strip()
        if password:
            usuario.password = password
        usuario.nombre = request.form['nombre'].strip()
        usuario.apellidos = request.form['apellidos'].strip()
        usuario.correo = request.form['correo'].strip()
        usuario.comision = request.form['comision'].strip()
        usuario.rol = request.form['rol'].strip()
        db.session.commit()
        flash('Usuario modificado correctamente.', 'success')
        return redirect(url_for('admin_panel'))
    return render_template('editar_usuario.html', usuario=usuario)


@app.route('/admin/usuarios/eliminar/<int:id>', methods=['POST'])
@login_required
@rol_required('admin', 'master')
def eliminar_usuario(id):
    usuario = Usuario.query.get_or_404(id)
    if not puede_eliminar_usuario(usuario):
        flash('No autorizado para eliminar este usuario.', 'danger')
        return redirect(url_for('admin_panel'))
    db.session.delete(usuario)
    db.session.commit()
    flash('Usuario eliminado.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/reservas', methods=['GET', 'POST'])
@login_required
def gestionar_reservas():
    if request.method == 'POST':
        reserva_id = request.form.get('reserva_id')
        id_localizador_form = request.form.get('id_localizador', '').strip()
        file = request.files.get('comprobante')

        if reserva_id:
            reserva = Reserva.query.get(reserva_id)
            if not reserva or not puede_editar_reserva(reserva):
                flash('No autorizado.', 'danger')
                return redirect(url_for('gestionar_reservas'))

            if id_localizador_form != reserva.id_localizador:
                if Reserva.query.filter_by(id_localizador=id_localizador_form).first():
                    flash('El ID Localizador ya está en uso.', 'warning')
                    return redirect(url_for('gestionar_reservas'))

            reserva.id_localizador = id_localizador_form
            set_reserva_fields(reserva, request.form)

            nombre_archivo, error_mensaje = guardar_comprobante(file, reserva.id_localizador)
            if error_mensaje:
                flash(error_mensaje, 'danger')
            elif nombre_archivo:
                # Eliminar el comprobante anterior si existe y se sube uno nuevo
                if reserva.comprobante_venta and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], reserva.comprobante_venta)):
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], reserva.comprobante_venta))
                        flash(f'Comprobante anterior {reserva.comprobante_venta} eliminado.', 'info')
                    except OSError as e:
                        flash(f'Error al eliminar comprobante anterior: {e}', 'warning')
                reserva.comprobante_venta = nombre_archivo

        else:
            if not id_localizador_form or Reserva.query.filter_by(id_localizador=id_localizador_form).first():
                id_localizador_form = generar_localizador_unico()

            nueva_reserva = Reserva(usuario_id=current_user.id, id_localizador=id_localizador_form)
            set_reserva_fields(nueva_reserva, request.form)

            nombre_archivo, error_mensaje = guardar_comprobante(file, id_localizador_form)
            if error_mensaje:
                flash(error_mensaje, 'danger')
            elif nombre_archivo:
                nueva_reserva.comprobante_venta = nombre_archivo

            db.session.add(nueva_reserva)

        db.session.commit()
        flash('Reserva guardada.', 'success')
        return redirect(url_for('gestionar_reservas'))

    search_query = request.args.get('search', '').strip()

    reservas_query = Reserva.query

    if current_user.rol not in ('admin', 'master'):
        reservas_query = reservas_query.filter_by(usuario_id=current_user.id)

    if search_query:
        reservas_query = reservas_query.filter(
            db.or_(
                Reserva.id_localizador.ilike(f'%{search_query}%'),
                Reserva.producto.ilike(f'%{search_query}%'),
                Reserva.nombre_pasajero.ilike(f'%{search_query}%'),
                Reserva.destino.ilike(f'%{search_query}%'),
                Reserva.nombre_ejecutivo.ilike(f'%{search_query}%')
            )
        )

    page = request.args.get('page', 1, type=int)
    reservas_paginated = reservas_query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    reservas = reservas_paginated.items

    editar_id = request.args.get('editar')
    editar_reserva = None
    if editar_id:
        reserva_a_editar = Reserva.query.get(int(editar_id))
        if reserva_a_editar and puede_editar_reserva(reserva_a_editar):
            editar_reserva = reserva_a_editar

    return render_template('reservas.html', reservas=reservas, editar_reserva=editar_reserva, pagination=reservas_paginated, search_query=search_query)


@app.route('/reservas/eliminar/<int:id>', methods=['POST'])
@login_required
def eliminar_reserva(id):
    reserva = Reserva.query.get_or_404(id)
    if not puede_editar_reserva(reserva):
        flash('No autorizado.', 'danger')
        return redirect(url_for('gestionar_reservas'))

    # Eliminar el archivo de comprobante si existe
    if reserva.comprobante_venta:
        ruta_comprobante = os.path.join(app.config['UPLOAD_FOLDER'], reserva.comprobante_venta)
        if os.path.exists(ruta_comprobante):
            os.remove(ruta_comprobante)
            flash(f'Comprobante {reserva.comprobante_venta} eliminado del servidor.', 'info')

    db.session.delete(reserva)
    db.session.commit()
    flash('Reserva eliminada.', 'success')
    return redirect(url_for('gestionar_reservas'))


@app.route('/exportar_reservas')
@login_required
def exportar_reservas():
    reservas = Reserva.query.all() if current_user.rol in ('admin', 'master') else Reserva.query.filter_by(usuario_id=current_user.id).all()

    data = [{
        'ID Localizador': r.id_localizador,
        'Usuario': r.usuario.username,
        'Fecha de viaje': r.fecha_viaje,
        'Producto': r.producto,
        'Fecha de venta': r.fecha_venta,
        'Modalidad de pago': r.modalidad_pago,
        'Nombre de pasajero': r.nombre_pasajero,
        'Teléfono de pasajero': r.telefono_pasajero,
        'Mail Pasajero': r.mail_pasajero,
        'Precio venta total': r.precio_venta_total,
        'Hotel neto': r.hotel_neto,
        'Vuelo neto': r.vuelo_neto,
        'Traslado neto': r.traslado_neto,
        'Seguro neto': r.seguro_neto,
        'Circuito Neto': r.circuito_neto,
        'Crucero Neto': r.crucero_neto,
        'Excursion Neto': r.excursion_neto,
        'Paquete Neto': r.paquete_neto,
        'Localizadores': r.localizadores,
        'Nombre ejecutivo': r.nombre_ejecutivo,
        'Correo ejecutivo': r.correo_ejecutivo,
        'Destino': r.destino,
        'Estado de pago': r.estado_pago,           # Nuevo campo en exportación
        'Venta cobrada': r.venta_cobrada,          # Nuevo campo en exportación
        'Venta emitida': r.venta_emitida           # Nuevo campo en exportación
    } for r in reservas]

    df = pd.DataFrame(data)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Reservas')
    output.seek(0)

    return send_file(
        output,
        as_attachment=True,
        download_name='reservas.xlsx',
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )


@app.route('/comprobantes/<filename>')
@login_required
def descargar_comprobante(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@app.route('/control_gestion_clientes')
@login_required
@rol_required('admin', 'master')
def control_gestion_clientes():
    ejecutivo_id = request.args.get('ejecutivo_id', type=int)
    rango_fechas_str = request.args.get('rango_fechas', 'ultimos_30_dias')

    reservas_query = Reserva.query.join(Usuario)

    if ejecutivo_id:
        reservas_query = reservas_query.filter(Reserva.usuario_id == ejecutivo_id)

    start_date, end_date = _get_date_range(rango_fechas_str)
    # Assuming fecha_venta is stored as 'YYYY-MM-DD'
    reservas_query = reservas_query.filter(Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
                                           Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d'))

    reservas = reservas_query.order_by(Reserva.fecha_venta.desc()).all()

    return render_template('control_gestion_clientes.html',
                           reservas=reservas,
                           ejecutivo_id=ejecutivo_id,
                           rango_fechas_str=rango_fechas_str)

@app.route('/panel_comisiones')
@login_required
@rol_required('admin', 'master')
def panel_comisiones():
    ejecutivo_id = request.args.get('ejecutivo_id', type=int)
    rango_fechas_str = request.args.get('rango_fechas', 'ultimos_30_dias')

    reservas_query = Reserva.query.join(Usuario)

    if ejecutivo_id:
        reservas_query = reservas_query.filter(Reserva.usuario_id == ejecutivo_id)

    start_date, end_date = _get_date_range(rango_fechas_str)
    reservas_query = reservas_query.filter(Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
                                           Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d'))

    reservas = reservas_query.order_by(Reserva.fecha_venta.desc()).all()

    # Calcular comisiones y ganancias
    datos_comisiones = []
    for reserva in reservas:
        comision_ejecutivo_porcentaje = 0.0
        if reserva.usuario.comision and reserva.usuario.comision.replace('.', '', 1).isdigit():
            comision_ejecutivo_porcentaje = float(reserva.usuario.comision) / 100.0

        # Suma de todos los netos
        total_neto = (
            reserva.hotel_neto +
            reserva.vuelo_neto +
            reserva.traslado_neto +
            reserva.seguro_neto +
            reserva.circuito_neto +
            reserva.crucero_neto +
            reserva.excursion_neto +
            reserva.paquete_neto
        )

        ganancia_bruta = reserva.precio_venta_total - total_neto
        comision_usuario = ganancia_bruta * comision_ejecutivo_porcentaje
        ganancia_neta = ganancia_bruta - comision_usuario

        datos_comisiones.append({
            'reserva': reserva,
            'total_neto': total_neto,
            'ganancia_bruta': ganancia_bruta,
            'comision_usuario': comision_usuario,
            'ganancia_neta': ganancia_neta
        })

    return render_template('panel_comisiones.html',
                           datos_comisiones=datos_comisiones,
                           ejecutivo_id=ejecutivo_id,
                           rango_fechas_str=rango_fechas_str)

@app.route('/marketing')
@login_required
@rol_required('admin', 'master')
def marketing():
    ejecutivo_id = request.args.get('ejecutivo_id', type=int)
    rango_fechas_str = request.args.get('rango_fechas', 'ultimos_30_dias')

    reservas_query = Reserva.query.join(Usuario)

    if ejecutivo_id:
        reservas_query = reservas_query.filter(Reserva.usuario_id == ejecutivo_id)

    start_date, end_date = _get_date_range(rango_fechas_str)
    reservas_query = reservas_query.filter(Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
                                           Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d'))

    reservas = reservas_query.order_by(Reserva.fecha_venta.desc()).all()

    return render_template('marketing.html',
                           reservas=reservas,
                           ejecutivo_id=ejecutivo_id,
                           rango_fechas_str=rango_fechas_str)

@app.route('/reporte_detalle_ventas')
@login_required
@rol_required('admin', 'master')
def reporte_detalle_ventas():
    selected_mes_str = request.args.get('mes', '')
    
    # Convert month string to start and end dates for the month
    try:
        month_name, year_str = selected_mes_str.split(' ')
        month_num = datetime.strptime(month_name, '%B').month
        year = int(year_str)
        start_date = datetime(year, month_num, 1)
        if month_num == 12:
            end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = datetime(year, month_num + 1, 1) - timedelta(days=1)
    except Exception:
        # Si no hay mes válido, mostrar la página con datos vacíos y el filtro
        return render_template('reporte_detalle_ventas.html',
                               reporte_data=[],
                               totales={
                                   'total_ventas_global': 0.0,
                                   'total_costos_global': 0.0,
                                   'total_comisiones_global': 0.0,
                                   'total_ganancia_neta_global': 0.0,
                                   'total_ventas_realizadas_global': 0
                               },
                               selected_mes_str=selected_mes_str)

    # Query all users (executives) to iterate through them
    ejecutivos = Usuario.query.filter(Usuario.rol.in_(['usuario', 'admin'])).order_by(Usuario.nombre).all()

    reporte_data = []
    total_ventas_global = 0.0
    total_costos_global = 0.0
    total_comisiones_global = 0.0
    total_ganancia_neta_global = 0.0
    total_ventas_realizadas_global = 0

    for ejecutivo in ejecutivos:
        reservas_ejecutivo = Reserva.query.filter(
            Reserva.usuario_id == ejecutivo.id,
            Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
            Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d')
        ).all()

        ventas_ejecutivo = 0.0
        costos_ejecutivo = 0.0
        comisiones_ejecutivo = 0.0
        ganancia_neta_ejecutivo = 0.0
        num_ventas_ejecutivo = len(reservas_ejecutivo)

        comision_porcentaje = 0.0
        if ejecutivo.comision and ejecutivo.comision.replace('.', '', 1).isdigit():
            comision_porcentaje = float(ejecutivo.comision) / 100.0

        for reserva in reservas_ejecutivo:
            ventas_ejecutivo += reserva.precio_venta_total
            
            # Suma de todos los netos para costos
            costos_reserva = (
                reserva.hotel_neto +
                reserva.vuelo_neto +
                reserva.traslado_neto +
                reserva.seguro_neto +
                reserva.circuito_neto +
                reserva.crucero_neto +
                reserva.excursion_neto +
                reserva.paquete_neto
            )
            costos_ejecutivo += costos_reserva

            ganancia_bruta_reserva = reserva.precio_venta_total - costos_reserva
            comision_reserva = ganancia_bruta_reserva * comision_porcentaje
            ganancia_neta_reserva = ganancia_bruta_reserva - comision_reserva

            comisiones_ejecutivo += comision_reserva
            ganancia_neta_ejecutivo += ganancia_neta_reserva
        
        reporte_data.append({
            'ejecutivo': ejecutivo,
            'total_ventas': ventas_ejecutivo,
            'total_costos': costos_ejecutivo,
            'total_comisiones': comisiones_ejecutivo,
            'ganancia_neta': ganancia_neta_ejecutivo,
            'num_ventas': num_ventas_ejecutivo
        })

        total_ventas_global += ventas_ejecutivo
        total_costos_global += costos_ejecutivo
        total_comisiones_global += comisiones_ejecutivo
        total_ganancia_neta_global += ganancia_neta_ejecutivo
        total_ventas_realizadas_global += num_ventas_ejecutivo

    totales = {
        'total_ventas_global': total_ventas_global,
        'total_costos_global': total_costos_global,
        'total_comisiones_global': total_comisiones_global,
        'total_ganancia_neta_global': total_ganancia_neta_global,
        'total_ventas_realizadas_global': total_ventas_realizadas_global
    }

    return render_template('reporte_detalle_ventas.html',
                           reporte_data=reporte_data,
                           totales=totales,
                           selected_mes_str=selected_mes_str)

@app.route('/reporte_ventas_general_mensual')
@login_required
@rol_required('admin', 'master')
def reporte_ventas_general_mensual():
    selected_mes_str = request.args.get('mes', '')
    try:
        month_name, year_str = selected_mes_str.split(' ')
        month_num = datetime.strptime(month_name, '%B').month
        year = int(year_str)
        start_date = datetime(year, month_num, 1)
        if month_num == 12:
            end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = datetime(year, month_num + 1, 1) - timedelta(days=1)
    except Exception:
        return render_template('reporte_ventas_general_mensual.html',
                               ganancia_total_mes=0.0,
                               selected_mes_str=selected_mes_str)

    reservas_mes = Reserva.query.filter(
        Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
        Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d')
    ).all()

    ganancia_total_mes = 0.0
    for reserva in reservas_mes:
        total_neto = (
            reserva.hotel_neto +
            reserva.vuelo_neto +
            reserva.traslado_neto +
            reserva.seguro_neto +
            reserva.circuito_neto +
            reserva.crucero_neto +
            reserva.excursion_neto +
            reserva.paquete_neto
        )
        ganancia_total_mes += (reserva.precio_venta_total - total_neto)

    return render_template('reporte_ventas_general_mensual.html',
                           ganancia_total_mes=ganancia_total_mes,
                           selected_mes_str=selected_mes_str)

@app.route('/ranking_ejecutivos')
@login_required
@rol_required('admin', 'master')
def ranking_ejecutivos():
    selected_mes_str = request.args.get('mes', '')
    try:
        month_name, year_str = selected_mes_str.split(' ')
        month_num = datetime.strptime(month_name, '%B').month
        year = int(year_str)
        start_date = datetime(year, month_num, 1)
        if month_num == 12:
            end_date = datetime(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = datetime(year, month_num + 1, 1) - timedelta(days=1)
    except Exception:
        return render_template('ranking_ejecutivos.html',
                               ranking_data=[],
                               selected_mes_str=selected_mes_str)

    ejecutivos = Usuario.query.filter(Usuario.rol.in_(['usuario', 'admin'])).order_by(Usuario.nombre).all()

    ranking_data = []
    for ejecutivo in ejecutivos:
        reservas_ejecutivo = Reserva.query.filter(
            Reserva.usuario_id == ejecutivo.id,
            Reserva.fecha_venta >= start_date.strftime('%Y-%m-%d'),
            Reserva.fecha_venta <= end_date.strftime('%Y-%m-%d')
        ).all()

        num_ventas = len(reservas_ejecutivo)
        ganancia_neta_ejecutivo = 0.0

        comision_porcentaje = 0.0
        if ejecutivo.comision and ejecutivo.comision.replace('.', '', 1).isdigit():
            comision_porcentaje = float(ejecutivo.comision) / 100.0

        for reserva in reservas_ejecutivo:
            total_neto = (
                reserva.hotel_neto +
                reserva.vuelo_neto +
                reserva.traslado_neto +
                reserva.seguro_neto +
                reserva.circuito_neto +
                reserva.crucero_neto +
                reserva.excursion_neto +
                reserva.paquete_neto
            )
            ganancia_bruta_reserva = reserva.precio_venta_total - total_neto
            comision_reserva = ganancia_bruta_reserva * comision_porcentaje
            ganancia_neta_ejecutivo += (ganancia_bruta_reserva - comision_reserva)

        ranking_data.append({
            'ejecutivo': ejecutivo,
            'num_ventas': num_ventas,
            'ganancia_neta': ganancia_neta_ejecutivo
        })
    
    # Sort by ganancia_neta_ejecutivo (descending) for ranking
    ranking_data.sort(key=lambda x: x['ganancia_neta'], reverse=True)

    return render_template('ranking_ejecutivos.html',
                           ranking_data=ranking_data,
                           selected_mes_str=selected_mes_str)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = Usuario.query.filter_by(correo=email).first()
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            send_reset_email(user, reset_url)
            flash('Se ha enviado un correo electrónico con instrucciones para restablecer tu contraseña.', 'info')
        else:
            flash('No se encontró una cuenta con ese correo electrónico.', 'danger')
    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash('El enlace de restablecimiento de contraseña es inválido o ha expirado.', 'danger')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        password = request.form['password']
        user = Usuario.query.filter_by(correo=email).first()
        if user:
            user.password = password
            db.session.commit()
            flash('Tu contraseña ha sido actualizada.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html')


# Función para enviar el correo de restablecimiento

def send_reset_email(user, reset_url):
    msg = Message('Restablecer tu contraseña', sender='noreply@example.com', recipients=[user.correo])
    msg.body = f'Para restablecer tu contraseña, haz clic en el siguiente enlace: {reset_url}'
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True)
