import time
from datetime import datetime
from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash
from models.usuario_model import UsuarioModel


# ====================================================================
# DECORADORES DE SEGURIDAD (CONTROL DE ACCESO - OWASP A01)
# ====================================================================

def login_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario_id' not in session:
            flash("Debes iniciar sesión para acceder.", "error")
            return redirect(url_for('login_view'))
        return f(*args, **kwargs)
    return decorada


def admin_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if session.get('usuario_rol') != 'admin':
            flash("Acceso denegado: permisos insuficientes.", "error")
            return redirect(url_for('index_view'))
        return f(*args, **kwargs)
    return decorada


# ====================================================================
# AUTENTICACIÓN Y SESIÓN (OWASP A07 & A09)
# ====================================================================

def login_view():
    ip_origen = request.remote_addr or '127.0.0.1'

    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        password = request.form.get('password', '')

        try:
            usuario = UsuarioModel.get_by_email(correo)
        except Exception:
            usuario = None

        # 1. Validación de existencia de usuario
        if not usuario:
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', 'Usuario no registrado')
            except Exception:
                pass
            flash("Credenciales incorrectas.", "error")
            return render_template('login.html')

        # 2. Control de bloqueo temporal por fuerza bruta
        bloqueado_hasta = usuario.get('bloqueado_hasta')
        if bloqueado_hasta and isinstance(bloqueado_hasta, datetime) and bloqueado_hasta > datetime.now():
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'ACCESO_DENEGADO', 'Intento de acceso a cuenta bloqueada')
            except Exception:
                pass
            flash("Cuenta bloqueada temporalmente por 5 intentos fallidos.", "error")
            return render_template('login.html')

        # 3. Verificación de hash Bcrypt
        pwd_hash = usuario.get('password_hash') or usuario.get('password') or ''
        es_valida = UsuarioModel.verify_password(password, pwd_hash)

        if es_valida:
            try:
                UsuarioModel.reiniciar_intentos(usuario['id'])
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'LOGIN_EXITOSO', 'Inicio de sesion exitoso')
            except Exception:
                pass

            session.clear()
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario.get('nombre', 'Usuario')
            session['usuario_rol'] = usuario.get('rol', 'usuario')
            return redirect(url_for('index_view'))

        # 4. Manejo de contraseña incorrecta e incremento de intentos
        intentos_actuales = usuario.get('intentos_fallidos') or 0
        try:
            UsuarioModel.incrementar_intentos(usuario['id'], intentos_actuales)
        except Exception:
            pass

        restantes = 5 - (intentos_actuales + 1)
        if restantes <= 0:
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'CUENTA_BLOQUEADA', 'Limite de 5 intentos alcanzado')
            except Exception:
                pass
            flash("Has superado el límite de 5 intentos. Cuenta bloqueada por 5 minutos.", "error")
        else:
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', f'Clave incorrecta. Restantes: {restantes}')
            except Exception:
                pass
            flash(f"Contraseña incorrecta. Te quedan {restantes} intento(s).", "error")

        return render_template('login.html')

    return render_template('login.html')


def logout_view():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for('login_view'))


# ====================================================================
# PANEL CRUD Y GESTIÓN DE USUARIOS
# ====================================================================

@login_requerido
def index_view():
    usuarios = UsuarioModel.get_all()
    return render_template('index.html', usuarios=usuarios, usuario_actual=session.get('usuario_nombre'))


@login_requerido
@admin_requerido
def agregar_view():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip()
        rol = request.form.get('rol', 'usuario').strip()
        password_default = "123456"

        if not nombre or not correo:
            flash("Nombre y correo son obligatorios.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.create(nombre, correo, password_default, rol)
            flash("Usuario creado correctamente.", "success")
        except Exception:
            flash("El correo electrónico ya se encuentra registrado.", "error")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def editar_view(id_usuario):
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip()
        rol = request.form.get('rol', 'usuario').strip()

        if not nombre or not correo:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for('index_view'))

        UsuarioModel.update(id_usuario, nombre, correo, rol)
        flash("Usuario actualizado con éxito.", "success")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def eliminar_view(id_usuario):
    if request.method == 'POST':
        UsuarioModel.delete(id_usuario)
        flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('index_view'))


# ====================================================================
# AUDITORÍA Y MONITOREO
# ====================================================================

@login_requerido
@admin_requerido
def auditoria_view():
    logs = UsuarioModel.get_auditoria()
    return render_template('auditoria.html', logs=logs, usuario_actual=session.get('usuario_nombre'))