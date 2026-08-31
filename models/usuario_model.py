import bcrypt
from config import get_db_connection

class UsuarioModel:

    @staticmethod
    def hash_password(password_plana):
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password_plana.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password_plana, hashed_password):
        try:
            if not hashed_password:
                return False
            return bcrypt.checkpw(password_plana.encode('utf-8'), hashed_password.encode('utf-8'))
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_all():
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, nombre, correo, rol FROM usuarios ORDER BY id DESC")
                return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_by_id(id_usuario):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, nombre, correo, rol FROM usuarios WHERE id = %s", (id_usuario,))
                return cursor.fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_by_email(correo):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM usuarios WHERE correo = %s", (correo,))
                return cursor.fetchone()
        finally:
            conn.close()

    @staticmethod
    def create(nombre, correo, password_plana, rol='usuario'):
        hashed_password = UsuarioModel.hash_password(password_plana)
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (%s, %s, %s, %s)",
                    (nombre, correo, hashed_password, rol)
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

    @staticmethod
    def incrementar_intentos(id_usuario, intentos_actuales):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                nuevos_intentos = intentos_actuales + 1
                if nuevos_intentos >= 5:
                    cursor.execute("""
                        UPDATE usuarios 
                        SET intentos_fallidos = %s, 
                            bloqueado_hasta = DATE_ADD(NOW(), INTERVAL 5 MINUTE) 
                        WHERE id = %s
                    """, (nuevos_intentos, id_usuario))
                else:
                    cursor.execute("""
                        UPDATE usuarios 
                        SET intentos_fallidos = %s 
                        WHERE id = %s
                    """, (nuevos_intentos, id_usuario))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def reiniciar_intentos(id_usuario):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE usuarios 
                    SET intentos_fallidos = 0, bloqueado_hasta = NULL 
                    WHERE id = %s
                """, (id_usuario,))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def registrar_auditoria(correo, ip, evento, descripcion):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO auditoria_accesos (correo, ip_origen, evento, descripcion)
                    VALUES (%s, %s, %s, %s)
                """, (correo, ip, evento, descripcion))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def get_auditoria():
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM auditoria_accesos ORDER BY fecha DESC")
                return cursor.fetchall()
        finally:
            conn.close() 