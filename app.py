import os
from flask import Flask, render_template
from dotenv import load_dotenv
from controllers.usuario_controller import (
    login_view, logout_view, index_view, 
    agregar_view, editar_view, eliminar_view, auditoria_view
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'clave_por_defecto_segura')

# A02: Cookies seguras
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False  # Cambiar a True cuando se use HTTPS
)

# Rutas
app.add_url_rule('/login', view_func=login_view, methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=logout_view, methods=['GET'])
app.add_url_rule('/', view_func=index_view, methods=['GET'])
app.add_url_rule('/agregar', view_func=agregar_view, methods=['POST'])
app.add_url_rule('/editar/<int:id_usuario>', view_func=editar_view, methods=['POST'])
app.add_url_rule('/eliminar/<int:id_usuario>', view_func=eliminar_view, methods=['POST'])
app.add_url_rule('/auditoria', view_func=auditoria_view, methods=['GET'])

# A10: Manejo controlado de condiciones excepcionales
@app.errorhandler(404)
def error_404(e):
    return render_template('error.html', error_codigo=404, mensaje="Página no encontrada"), 404

@app.errorhandler(500)
def error_500(e):
    return render_template('error.html', error_codigo=500, mensaje="Error interno del servidor procesado de forma segura"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)