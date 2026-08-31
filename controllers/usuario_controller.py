from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash
from models.usuario_model import UsuarioModel
from datetime import datetime

def login_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario_id' not in session:
            flash("Debes iniciar sesión para acceder.", "error")
            return redirect(url_for('login_view'))
        return f(*args, **kwargs)
    return decorada

from datetime import datetime

def login_view():
    ip_origen = request.remote_addr or 'Desconocida'

    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        password = request.form.get('password', '')

        usuario = UsuarioModel.get_by_email(correo)

        if not usuario:
            UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', 'Usuario no encontrado')
            flash("Credenciales incorrectas.", "error")
            return render_template('login.html')

        # Comprobar bloqueo previo
        if usuario.get('bloqueado_hasta') and usuario['bloqueado_hasta'] > datetime.now():
            UsuarioModel.registrar_auditoria(correo, ip_origen, 'ACCESO_DENEGADO', 'Intento de acceso a cuenta bloqueada')
            flash("Cuenta temporalmente bloqueada por demasiados intentos fallidos (5 min).", "error")
            return render_template('login.html')

        # Validar contraseña
        if UsuarioModel.verify_password(password, usuario['password_hash']):
            UsuarioModel.reiniciar_intentos(usuario['id'])
            UsuarioModel.registrar_auditoria(correo, ip_origen, 'LOGIN_EXITOSO', 'Inicio de sesión correcto')
            
            session.clear()
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario['nombre']
            session['usuario_rol'] = usuario['rol']
            return redirect(url_for('index_view'))
        else:
            intentos_actuales = usuario.get('intentos_fallidos', 0)
            UsuarioModel.incrementar_intentos(usuario['id'], intentos_actuales)
            
            restantes = 5 - (intentos_actuales + 1)
            if restantes <= 0:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'CUENTA_BLOQUEADA', 'Bloqueo temporal activado (5 intentos)')
                flash("Has superado el límite de 5 intentos. Cuenta bloqueada por 5 minutos.", "error")
            else:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', f'Contraseña errónea. Restantes: {restantes}')
                flash(f"Contraseña incorrecta. Te quedan {restantes} intento(s).", "error")

            return render_template('login.html')

    return render_template('login.html')

@login_requerido
def auditoria_view():
    logs = UsuarioModel.get_auditoria()
    return render_template('auditoria.html', logs=logs, usuario_actual=session.get('usuario_nombre'))


def logout_view():
    session.clear()
    return redirect(url_for('login_view'))

@login_requerido
def index_view():
    usuarios = UsuarioModel.get_all()
    return render_template('index.html', usuarios=usuarios, usuario_actual=session.get('usuario_nombre'))

@login_requerido
def agregar_view():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip()
        password = request.form.get('password', '')
        rol = request.form.get('rol', 'usuario')

        if not nombre or not correo or not password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.create(nombre, correo, password, rol)
            flash("Usuario creado correctamente.", "success")
        except Exception:
            flash("El correo electrónico ya se encuentra registrado.", "error")

    return redirect(url_for('index_view'))

@login_requerido
def editar_view(id_usuario):
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip()
        rol = request.form.get('rol', 'usuario').strip()

        if not nombre or not correo:
            flash("Nombre y correo son obligatorios.", "error")
        else:
            try:
                UsuarioModel.update(id_usuario, nombre, correo, rol)
                flash(f"Usuario #{id_usuario} actualizado correctamente.", "success")
            except Exception:
                flash("Error al actualizar. Posible correo duplicado.", "error")

    return redirect(url_for('index_view'))

@login_requerido
def eliminar_view(id_usuario):
    if session.get('usuario_id') == id_usuario:
        flash("No puedes eliminar tu propio usuario activo.", "error")
    else:
        UsuarioModel.delete(id_usuario)
        flash("Usuario eliminado.", "success")
    return redirect(url_for('index_view'))


@login_requerido
def auditoria_view():
    # Comprobar que el usuario tenga rol de administrador
    if session.get('usuario_rol') != 'admin':
        flash("Acceso denegado: solo administradores pueden ver la auditoría.", "error")
        return redirect(url_for('index_view'))

    logs = UsuarioModel.get_auditoria()
    return render_template('auditoria.html', logs=logs, usuario_actual=session.get('usuario_nombre'))    