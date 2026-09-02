import re
import logging
from datetime import datetime, timezone
from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash
from models.usuario_model import UsuarioModel

logger = logging.getLogger(__name__)

# [OWASP A09: Identificación precisa de la IP real considerando proxies inversos]
def obtener_ip_origen():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr) or '127.0.0.1'
    return ip.split(',')[0].strip() if ',' in ip else ip


# --- DECORADORES DE SEGURIDAD (OWASP A01) ---

# [OWASP A01: Control de acceso para requerir autenticación previa]
def login_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario_id' not in session:
            flash("Debes iniciar sesión para acceder.", "error")
            return redirect(url_for('login_view'))
        return f(*args, **kwargs)
    return decorada

# [OWASP A01 & A09: Control RBAC exclusivo para administradores y registro de accesos no autorizados]
def admin_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if session.get('usuario_rol') != 'admin':
            ip_origen = obtener_ip_origen()
            correo = session.get('usuario_nombre', 'Desconocido')
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'ACCESO_DENEGADO', f'Intento de acceso no autorizado a {request.path}')
            except Exception as e:
                logger.error(f"Error al registrar auditoría de acceso denegado: {e}")
            flash("Acceso denegado: permisos insuficientes.", "error")
            return redirect(url_for('index_view'))
        return f(*args, **kwargs)
    return decorada


# --- AUTENTICACIÓN Y SESIÓN (OWASP A04, A07, A09) ---

def login_view():
    ip_origen = obtener_ip_origen()

    if request.method == 'POST':
        correo = request.form.get('correo', '').strip().lower()
        password = request.form.get('password', '')
        
        # [OWASP A04: Mensaje genérico contra enumeración de usuarios válidos]
        mensaje_error_generico = "Credenciales incorrectas o cuenta temporalmente suspendida."

        if not correo or not password:
            flash(mensaje_error_generico, "error")
            return render_template('login.html')

        try:
            usuario = UsuarioModel.get_by_email(correo)
        except Exception as e:
            logger.error(f"Error en consulta de autenticación: {e}")
            usuario = None

        # [OWASP A09: Registro de fallos de inicio de sesión de cuentas inexistentes]
        if not usuario:
            try:
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'FALLO_LOGIN', 'Usuario no registrado')
            except Exception as e:
                logger.error(f"Error al registrar auditoría: {e}")
            flash(mensaje_error_generico, "error")
            return render_template('login.html')

        # [OWASP A04 & A07: Control de bloqueo temporal por fuerza bruta]
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

        # [OWASP A02: Comparación segura de hash con Bcrypt]
        pwd_hash = usuario.get('password_hash') or ''
        es_valida = UsuarioModel.verify_password(password, pwd_hash)

        if es_valida:
            try:
                UsuarioModel.reiniciar_intentos(usuario['id'])
                # [OWASP A09: Auditoría de acceso exitoso]
                UsuarioModel.registrar_auditoria(correo, ip_origen, 'LOGIN_EXITOSO', 'Autenticación exitosa')
            except Exception as e:
                logger.error(f"Error actualizando estado de login: {e}")

            # [OWASP A07: Renovación completa de sesión para prevenir Session Fixation]
            session.clear()
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario.get('nombre', 'Usuario')
            session['usuario_rol'] = usuario.get('rol', 'usuario')
            return redirect(url_for('index_view'))

        # [OWASP A04 & A09: Registro de contraseña errónea e incremento atómico de intentos]
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


# [OWASP A07 & A09: Cierre seguro, destrucción de sesión y trazabilidad de salida]
def logout_view():
    correo = session.get('usuario_nombre', 'Sesión')
    ip_origen = obtener_ip_origen()
    try:
        UsuarioModel.registrar_auditoria(correo, ip_origen, 'LOGOUT', 'Cierre de sesión seguro')
    except Exception as e:
        logger.error(f"Error registrando logout: {e}")
        
    session.clear()
    flash("Sesión finalizada de forma segura.", "success")
    return redirect(url_for('login_view'))


# --- PANEL CRUD (OWASP A01, A03, A09) ---

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
        password_default = "123456"
        ip_origen = obtener_ip_origen()
        admin_actual = session.get('usuario_nombre', 'Admin')

        # [OWASP A03: Validación estricta mediante expresiones regulares de la entrada]
        patron_correo = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not nombre or not correo or not re.match(patron_correo, correo):
            flash("Datos de entrada inválidos o formato de correo incorrecto.", "error")
            return redirect(url_for('index_view'))

        # [OWASP A01: Validación en lista blanca del rol asignado]
        if rol not in ['admin', 'usuario']:
            flash("Rol no autorizado.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.create(nombre, correo, password_default, rol)
            # [OWASP A09: Auditoría de creación de cuentas]
            UsuarioModel.registrar_auditoria(admin_actual, ip_origen, 'CREAR_USUARIO', f'Creó al usuario: {correo} (Rol: {rol})')
            flash("Usuario registrado exitosamente con clave por defecto.", "success")
        except Exception as e:
            logger.error(f"Error al crear usuario: {e}")
            flash("Error: El correo electrónico ya se encuentra registrado o hubo un fallo en base de datos.", "error")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def editar_view(id_usuario):
    if request.method == 'POST':
        nombre = request.form.get('nombre', '').strip()
        correo = request.form.get('correo', '').strip().lower()
        rol = request.form.get('rol', 'usuario').strip()
        ip_origen = obtener_ip_origen()
        admin_actual = session.get('usuario_nombre', 'Admin')

        # [OWASP A03: Validación estricta de formato]
        patron_correo = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not nombre or not correo or not re.match(patron_correo, correo):
            flash("Datos de formulario inválidos.", "error")
            return redirect(url_for('index_view'))

        # [OWASP A01: Whitelist de perfiles]
        if rol not in ['admin', 'usuario']:
            flash("Rol no permitido.", "error")
            return redirect(url_for('index_view'))

        try:
            UsuarioModel.update(id_usuario, nombre, correo, rol)
            # [OWASP A09: Auditoría de cambios sobre registros]
            UsuarioModel.registrar_auditoria(admin_actual, ip_origen, 'ACTUALIZAR_USUARIO', f'Actualizó ID #{id_usuario}: {correo} (Rol: {rol})')
            flash("Registro actualizado correctamente.", "success")
        except Exception as e:
            logger.error(f"Error al actualizar: {e}")
            flash("Error al procesar la actualización del usuario.", "error")

    return redirect(url_for('index_view'))


@login_requerido
@admin_requerido
def eliminar_view(id_usuario):
    if request.method == 'POST':
        # [OWASP A01: Control de acceso para evitar que un admin borre su propia sesión activa]
        if id_usuario == session.get('usuario_id'):
            flash("Operación denegada: No puedes eliminar tu propia cuenta activa.", "error")
            return redirect(url_for('index_view'))

        ip_origen = obtener_ip_origen()
        admin_actual = session.get('usuario_nombre', 'Admin')

        try:
            UsuarioModel.delete(id_usuario)
            # [OWASP A09: Auditoría de eliminación de usuarios]
            UsuarioModel.registrar_auditoria(admin_actual, ip_origen, 'ELIMINAR_USUARIO', f'Eliminó al usuario con ID #{id_usuario}')
            flash("Usuario eliminado de la base de datos.", "success")
        except Exception as e:
            logger.error(f"Error al eliminar: {e}")
            flash("Error al procesar la eliminación.", "error")

    return redirect(url_for('index_view'))


# --- AUDITORÍA (OWASP A01, A09) ---

@login_requerido
@admin_requerido
def auditoria_view():
    logs = UsuarioModel.get_auditoria(limite=100)
    return render_template('auditoria.html', logs=logs, usuario_actual=session.get('usuario_nombre'))
