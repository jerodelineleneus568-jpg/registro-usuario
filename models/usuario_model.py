from config import get_db_connection

class UsuarioModel:

    @staticmethod
    def get_all():
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios ORDER BY id DESC")
                return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def create(nombre, correo, rol):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO usuarios (nombre, correo, rol) VALUES (%s, %s, %s)",
                    (nombre, correo, rol)
                )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def update(id_usuario, nombre, correo, rol):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE usuarios SET nombre = %s, correo = %s, rol = %s WHERE id = %s",
                    (nombre, correo, rol, id_usuario)
                )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def delete(id_usuario):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM usuarios WHERE id = %s", (id_usuario,))
            conn.commit()
        finally:
            conn.close()