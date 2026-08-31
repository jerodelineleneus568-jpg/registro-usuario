from flask import Blueprint, render_template, request, redirect, url_for
from models.usuario_model import UsuarioModel

usuario_bp = Blueprint('usuario_bp', __name__)

@usuario_bp.route('/')
def index():
    usuarios = UsuarioModel.get_all()
    return render_template('index.html', usuarios=usuarios)

@usuario_bp.route('/crear', methods=['POST'])
def crear():
    nombre = request.form.get('nombre')
    correo = request.form.get('correo')
    rol = request.form.get('rol')
    if nombre and correo and rol:
        UsuarioModel.create(nombre, correo, rol)
    return redirect(url_for('usuario_bp.index'))

@usuario_bp.route('/editar/<int:id>', methods=['POST'])
def editar(id):
    nombre = request.form.get('nombre')
    correo = request.form.get('correo')
    rol = request.form.get('rol')
    if nombre and correo and rol:
        UsuarioModel.update(id, nombre, correo, rol)
    return redirect(url_for('usuario_bp.index'))

@usuario_bp.route('/eliminar/<int:id>')
def eliminar(id):
    UsuarioModel.delete(id)
    return redirect(url_for('usuario_bp.index'))