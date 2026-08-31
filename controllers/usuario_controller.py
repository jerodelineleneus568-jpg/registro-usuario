from functools import wraps
from flask import render_template, request, redirect, url_for, session, flash
from models.usuario_model import UsuarioModel

def login_requerido(f):
    @wraps(f)
    def decorada(*args, **kwargs):
        if 'usuario_id' not in session:
            flash("Debes iniciar sesión para acceder.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorada

def login_view():
    if request.method == 'POST':
        correo = request.form.get('correo', '').strip()
        password = request.form.get('password', '')

        usuario = UsuarioModel.get_by_email(correo)

        if usuario and UsuarioModel.verify_password(password, usuario['password_hash']):
            session.clear()
            session['usuario_id'] = usuario['id']
            session['usuario_nombre'] = usuario['nombre']
            session['usuario_rol'] = usuario['rol']
            return redirect(url_for('index'))
        else:
            flash("Credenciales incorrectas.", "error")
            return render_template('login.html')

    return render_template('login.html')

def logout_view():
    session.clear()
    return redirect(url_for('login'))

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
            return redirect(url_for('index'))

        UsuarioModel.create(nombre, correo, password, rol)
        flash("Usuario creado correctamente.", "success")
        return redirect(url_for('index'))

@login_requerido
def eliminar_view(id_usuario):
    if session.get('usuario_id') == id_usuario:
        flash("No puedes eliminar tu propio usuario activo.", "error")
    else:
        UsuarioModel.delete(id_usuario)
        flash("Usuario eliminado.", "success")
    return redirect(url_for('index'))