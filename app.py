from flask import Flask, render_template, request, redirect, url_for
import pymysql

app = Flask(__name__)

DB_CONFIG = {
    'host': 'localhost',
    'user': 'admin_user',
    'password': 'TuPasword123',
    'database': 'app_db',
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db():
    return pymysql.connect(**DB_CONFIG)

@app.route('/')
def index():
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM usuarios")
        usuarios = cursor.fetchall()
    conn.close()
    return render_template('index.html', usuarios=usuarios)

@app.route('/crear', methods=['POST'])
def crear():
    nombre = request.form['nombre']
    correo = request.form['correo']
    rol = request.form['rol']
    
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute(
            "INSERT INTO usuarios (nombre, correo, rol) VALUES (%s, %s, %s)",
            (nombre, correo, rol)
        )
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/editar/<int:id>', methods=['POST'])
def editar(id):
    nombre = request.form['nombre']
    correo = request.form['correo']
    rol = request.form['rol']
    
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute(
            "UPDATE usuarios SET nombre = %s, correo = %s, rol = %s WHERE id = %s",
            (nombre, correo, rol, id)
        )
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

@app.route('/eliminar/<int:id>')
def eliminar(id):
    conn = get_db()
    with conn.cursor() as cursor:
        cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
