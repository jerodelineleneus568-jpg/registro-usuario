import bcrypt
import re
from config import get_db_connection

class UsuarioModel:

    # OWASP A07: Validación de fortaleza mínima de contraseña
    @staticmethod
    def validar_password_fuerte(password: str) -> bool:
        """Exige entre 8 y 128 caracteres, al menos una minúscula, una mayúscula, un número y un símbolo."""
        if not password or len(password) < 8 or len(password) > 128:
            return False
        
        tiene_minuscula = bool(re.search(r'[a-z]', password))
        tiene_mayuscula = bool(re.search(r'[A-Z]', password))
        tiene_numero = bool(re.search(r'\d', password))
        tiene_simbolo = bool(re.search(r'[@$!%*?&#/._-]', password))
        
        return tiene_minuscula and tiene_mayuscula and tiene_numero and tiene_simbolo

    # OWASP A02: Hashing con sal aleatoria y coste computacional elevado
    @staticmethod
    def hash_password(password_plana: str) -> str:
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password_plana.encode('utf-8'), salt).decode('utf-8')

    # OWASP A02: Verificación segura de hashes en tiempo constante
    @staticmethod
    def verify_password(password_plana, password_hash) -> bool:
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

    # OWASP A03: Consultas preparadas usando tuplas %s contra inyección SQL
    @staticmethod
    def get_all():
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, nombre, correo, rol, intentos_fallidos, bloqueado_hasta "
                    "FROM usuarios ORDER BY id DESC"
                )
                return cursor.fetchall()
        finally:
            conn.close()

    @staticmethod
    def get_by_id(id_usuario):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, nombre, correo, rol FROM usuarios WHERE id = %s", 
                    (int(id_usuario),)
                )
                return cursor.fetchone()
        finally:
            conn.close()

    @staticmethod
    def get_by_email(correo):
        if not correo:
            return None
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, nombre, correo, password_hash, rol, intentos_fallidos, bloqueado_hasta "
                    "FROM usuarios WHERE correo = %s", 
                    (correo.strip().lower(),)
                )
                return cursor.fetchone()
        finally:
            conn.close()

    # OWASP A02, A03 & A04: Almacenamiento seguro con rollback transaccional
    @staticmethod
    def create(nombre, correo, password_plana, rol='usuario'):
        hashed_password = UsuarioModel.hash_password(password_plana)
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (%s, %s, %s, %s)",
                    (nombre.strip(), correo.strip().lower(), hashed_password, rol)
                )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def update(id_usuario, nombre, correo, rol):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE usuarios SET nombre = %s, correo = %s, rol = %s WHERE id = %s",
                    (nombre.strip(), correo.strip().lower(), rol, int(id_usuario))
                )
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def delete(id_usuario):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM usuarios WHERE id = %s", (int(id_usuario),))
            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # OWASP A04 & A07: Operación atómica contra condiciones de carrera y bloqueo temporal
    @staticmethod
    def incrementar_intentos(id_usuario):
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
                """, (int(id_usuario),))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
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
                """, (int(id_usuario),))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # OWASP A09: Trazabilidad persistente de eventos
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
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def get_auditoria(limite=100):
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT id, correo, ip_origen, evento, descripcion, fecha "
                    "FROM auditoria_accesos ORDER BY fecha DESC LIMIT %s", 
                    (int(limite),)
                )
                return cursor.fetchall()
        finally:
            conn.close()