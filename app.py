from flask import Flask
from controllers.usuario_controller import usuario_bp

app = Flask(__name__)

# Registrar Blueprint
app.register_blueprint(usuario_bp)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)