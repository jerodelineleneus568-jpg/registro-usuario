import os
from flask import Flask
from controllers.usuario_controller import (
    login_view, logout_view, index_view, 
    agregar_view, editar_view, eliminar_view, auditoria_view
)

# 1. Primero se inicializa la aplicación Flask
app = Flask(__name__)
app.secret_key = 'clave_secreta_super_segura_12345'

# Configuración de cookies de sesión
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False
)

# 2. Rutas de Autenticación
app.add_url_rule('/login', view_func=login_view, methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=logout_view, methods=['GET'])

# 3. Rutas CRUD
app.add_url_rule('/', view_func=index_view, methods=['GET'])
app.add_url_rule('/agregar', view_func=agregar_view, methods=['POST'])
app.add_url_rule('/editar/<int:id_usuario>', view_func=editar_view, methods=['POST'])
app.add_url_rule('/eliminar/<int:id_usuario>', view_func=eliminar_view, methods=['POST'])

# 4. Ruta de Auditoría
app.add_url_rule('/auditoria', view_func=auditoria_view, methods=['GET'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)