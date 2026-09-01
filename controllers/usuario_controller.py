import re
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash
from models.usuario_model import UsuarioModel

logger = logging.getLogger(__name__)

# --- DECORADORES DE SEGURIDAD (OWASP A01) ---

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


# --- AUTENTICACIÓN Y SESIÓN (OWASP A07, A09) ---

def login_view():
    ip_origen = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    if ',' in ip_origen:
        ip_origen = ip_origen.split(',')[0].strip()

    if request.method == 'POST':
        correo = request.form.get('correo', '').strip().lower()
        password = request.form.get('password', '')

        mensaje_error_generico = "Credenciales incorrectas o cuenta temporalmente suspendida."

        if not correo or not password:
            flash(mensaje_error_generico, "error")
            return render_template('login.html')

        try:
            usuario = UsuarioModel.get_by_email(correo)
        except Exception as e:
            logger.error(f"Error en consulta de autenticación: {e}")
            usuario = None

        # 1. Validación de existencia
        if not usuario:
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', 'Usuario no registrado')
            except Exception as e:
                logger.error(f"Error al registrar auditoría: {e}")
            flash(mensaje_error_generico, "error")
            return render_template('login.html')

        # 2. Control de bloqueo temporal
        bloqueado_hasta = usuario.get('bloqueado_hasta')
        if bloqueado_hasta:
            ahora = datetime.now(timezone.utc).replace(tzinfo=None)
            if bloqueado_hasta > ahora:
                try:
                    UsuarioModel.registrar_auditoria(correo, ip_origen, 'ACCESO_DENEGADO', 'Intento sobre cuenta bloqueada')
                except Exception as e:
                    logger.error(f"Error al registrar auditoría: {e}")
                flash(mensaje_error_generico, "error")
                return render_template('login.html')

        # 3. Verificación de hash Bcrypt
        pwd_hash = usuario.get('password_hash') or ''
        es_valida = UsuarioModel.verify_password(password, pwd_hash)

        if es_valida:
            try:
                UsuarioModel.reiniciar_intentos(usuario['id'])
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'LOGIN_EXITOSO', 'Autenticación exitosa')
            except Exception as e:
                logger.error(f"Error actualizando estado de login: {e}")

            session.clear()
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario.get('nombre', 'Usuario')
            session['usuario_rol'] = usuario.get('rol', 'usuario')
            return redirect(url_for('index_view'))

        # 4. Manejo de contraseña errónea e incremento atómico
        try:
            UsuarioModel.incrementar_intentos(usuario['id'])
            intentos_actuales = (usuario.get('intentos_fallidos') or 0) + 1
            
            if intentos_actuales >= 5:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'CUENTA_BLOQUEADA', 'Bloqueo temporal aplicado')
            else:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', f'Intento fallido #{intentos_actuales}')
        except Exception as e:
            logger.error(f"Error registrando intento fallido: {e}")

        flash(mensaje_error_generico, "error")
        return render_template('login.html')

    return render_template('login.html')


def logout_view():
    session.clear()
    flash("Sesión finalizada de forma segura.", "success")
    return redirect(url_for('login_view'))


# --- PANEL CRUD (OWASP A01, A04, A08) ---

@login_requerido
def index_view():
    usuarios = UsuarioModel.get_all()
    return render_template('index.html', usuarios=usuarios, usuario_actual=session.get('usuario_nombre'))


@login_requerido
@admin_requerido
def agregar_view():
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip().lower()
        rol = request.form.get('rol', 'usuario').strip()
        password_default = "123456"  # Contraseña inicial predeterminada

        # Validación de campos y formato de correo
        patron_correo = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not nombre or not correo or not re.match(patron_correo, correo):
            flash("Datos de entrada inválidos o formato de correo incorrecto.", "error")
            return redirect(url_for('index_view'))

        if rol not in ['admin', 'usuario']:
            flash("Rol no autorizado.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.create(nombre, correo, password_default, rol)
            flash("Usuario registrado exitosamente con clave por defecto.", "success")
        except Exception:
            flash("Error: El correo electrónico ya se encuentra registrado.", "error")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def editar_view(id_usuario):
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip().lower()
        rol = request.form.get('rol', 'usuario').strip()

        patron_correo = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not nombre or not correo or not re.match(patron_correo, correo):
            flash("Datos de formulario inválidos.", "error")
            return redirect(url_for('index_view'))

        if rol not in ['admin', 'usuario']:
            flash("Rol no permitido.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.update(id_usuario, nombre, correo, rol)
            flash("Registro actualizado correctamente.", "success")
        except Exception as e:
            logger.error(f"Error al actualizar: {e}")
            flash("Error al procesar la actualización del usuario.", "error")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def eliminar_view(id_usuario):
    if request.method == 'POST':
        if id_usuario == session.get('usuario_id'):
            flash("Operación denegada: No puedes eliminar tu propia cuenta activa.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.delete(id_usuario)
            flash("Usuario eliminado de la base de datos.", "success")
        except Exception as e:
            logger.error(f"Error al eliminar: {e}")
            flash("Error al procesar la eliminación.", "error")

    return redirect(url_for('index_view'))


# --- AUDITORÍA (OWASP A09) ---

@login_requerido
@admin_requerido
def auditoria_view():
    logs = UsuarioModel.get_auditoria(limite=100)
    return render_template('auditoria.html', logs=logs, usuario_actual=session.get('usuario_nombre'))