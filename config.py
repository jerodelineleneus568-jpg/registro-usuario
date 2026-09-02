import os
import pymysql
import pymysql.cursors
from dotenv import load_dotenv

load_dotenv()

# [OWASP A02 & A05: Gestión segura de credenciales vía variables de entorno sin hardcoding]
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'admin_user'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'app_db'),
    # [OWASP A03: Previene inyecciones SQL basadas en fallos de codificación multibyte]
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,
    # [OWASP A05: Mitiga ataques DoS por agotamiento de sockets si la BD no responde]
    'connect_timeout': 5,
    # [OWASP A04: Transaccionalidad atómica obligatoria para evitar datos corruptos]
    'autocommit': False
}

def get_db_connection():
    try:
        return pymysql.connect(**DB_CONFIG)
    except pymysql.MySQLError as e:
        raise ConnectionError(f"Error conectando a la base de datos: {e}") from e