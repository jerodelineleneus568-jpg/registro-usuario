import os
from flask import Flask, render_template
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
from controllers.usuario_controller import (
    login_view, logout_view, index_view, 
    agregar_view, editar_view, eliminar_view, auditoria_view
)

load_dotenv()

app = Flask(__name__)

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    secret_key = os.urandom(32).hex()

app.secret_key = secret_key
csrf = CSRFProtect(app)

# Configuración estricta de Cookies y HTTPS
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=1800
)

# Cabeceras de Seguridad HTTP
@app.after_request
def agregar_cabeceras_seguridad(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
    )
    return response

# Enrutamiento hacia los controladores
app.add_url_rule('/login', view_func=login_view, methods=['GET', 'POST'])
app.add_url_rule('/logout', view_func=logout_view, methods=['GET'])
app.add_url_rule('/', view_func=index_view, methods=['GET'])
app.add_url_rule('/agregar', view_func=agregar_view, methods=['POST'])
app.add_url_rule('/editar/<int:id_usuario>', view_func=editar_view, methods=['POST'])
app.add_url_rule('/eliminar/<int:id_usuario>', view_func=eliminar_view, methods=['POST'])
app.add_url_rule('/auditoria', view_func=auditoria_view, methods=['GET'])

# Manejadores de error
@app.errorhandler(400)
def error_400(e):
    return render_template('error.html', error_codigo=400, mensaje="Petición inválida o token CSRF ausente/expirado."), 400

@app.errorhandler(404)
def error_404(e):
    return render_template('error.html', error_codigo=404, mensaje="El recurso solicitado no fue encontrado."), 404

@app.errorhandler(405)
def error_405(e):
    return render_template('error.html', error_codigo=405, mensaje="Método HTTP no autorizado para esta ruta."), 405

@app.errorhandler(500)
def error_500(e):
    return render_template('error.html', error_codigo=500, mensaje="Error interno del servidor procesado de forma segura."), 500

if __name__ == '__main__':
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'), debug=False)
    else:
        app.run(host='0.0.0.0', port=5000, debug=False)