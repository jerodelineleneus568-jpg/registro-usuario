import bcrypt
import re
from config import get_db_connection

class UsuarioModel:

    @staticmethod
    def validar_password_fuerte(password: str) -> bool:
        """Exige mínimo 8 caracteres, al menos una mayúscula, un número y un caracter especial."""
        if len(password) < 8:
            return False
        patron = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#/._-]).{8,}$'
        return bool(re.match(patron, password))

    @staticmethod
    def hash_password(password_plana):
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password_plana.encode('utf-8'), salt).decode('utf-8')

    @staticmethod
    def verify_password(password_plana, password_hash):
        if not password_plana or not password_hash:
            return False
        if isinstance(password_hash, str):
            password_hash = password_hash.encode('utf-8')
        if isinstance(password_plana, str):
            password_plana = password_plana.encode('utf-8')
        try:
            return bcrypt.checkpw(password_plana, password_hash)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_all():
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, nombre, correo, rol, intentos_fallidos, bloqueado_hasta FROM usuarios ORDER BY id DESC")
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
                cursor.execute("SELECT id, nombre, correo, password_hash, rol, intentos_fallidos, bloqueado_hasta FROM usuarios WHERE correo = %s", (correo,))
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
    def incrementar_intentos(id_usuario):
        """Operación atómica en BD: evita condiciones de carrera (OWASP A04)."""
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    UPDATE usuarios 
                    SET intentos_fallidos = intentos_fallidos + 1,
                        bloqueado_hasta = CASE 
                            WHEN intentos_fallidos + 1 >= 5 THEN DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE)
                            ELSE bloqueado_hasta 
                        END
                    WHERE id = %s
                """, (id_usuario,))
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
                    INSERT INTO auditoria_accesos (correo, ip_origen, evento, descripcion, fecha)
                    VALUES (%s, %s, %s, %s, UTC_TIMESTAMP())
                """, (correo, ip, evento, descripcion))
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def get_auditoria(limite=100):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, correo, ip_origen, evento, descripcion, fecha FROM auditoria_accesos ORDER BY fecha DESC LIMIT %s", (limite,))
                return cursor.fetchall()
        finally:
            conn.close()