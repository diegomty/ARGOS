"""Configuración del laboratorio EVE-NG y umbrales de detección.

Las credenciales del router pueden sobreescribirse por variables de entorno
para evitar exponerlas al subir el código a un repo público:

    Q_SENTINEL_ROUTER_USER=admin
    Q_SENTINEL_ROUTER_PASS=root
"""

import os

# --- Red local ---
IP_ESCUCHA = "0.0.0.0"
PUERTO_SYSLOG = 514
MI_PC_IP = "192.168.128.1"

# --- Router Cisco 7200 (administración SSH) ---
#
# NOTA: los defaults `admin`/`root` son SOLO para el lab EVE-NG. En
# cualquier despliegue real, sobreescribe estos valores con variables
# de entorno (Q_SENTINEL_ROUTER_USER / Q_SENTINEL_ROUTER_PASS) o un
# vault de secretos. Nunca commitees credenciales reales al repo.
IP_ROUTER_ADMIN = "192.168.128.100"
USER_ROUTER = os.getenv("Q_SENTINEL_ROUTER_USER", "admin")
PASS_ROUTER = os.getenv("Q_SENTINEL_ROUTER_PASS", "root")
INTERFAZ_BLOQUEO = "f0/1"

# --- Heurística de filtrado ---
PALABRAS_CONFIANZA = (
    "tftp",
    "CONFIG_I",
    "SYS-5-RESTART",
    "Line protocol",
    "SSH_SESSION",
    "SSH_USERAUTH",
    "SSH2_CLOSE",
    "LOGIN_SUCCESS",
    "CDP-4-DUPLEX",
    "DUPLEX_MISMATCH",
)

# --- Detección ---
UMBRAL_ENTROPIA = 5.0  # bits — H(X) por encima dispara análisis de origen
IP_ATACANTE_FALLBACK = "10.0.0.2"  # Plan B cuando el origen viene como UNKNOWN
