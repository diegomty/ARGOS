"""Inyecta los 25 registros de la actividad como mensajes syslog reales
hacia el listener UDP/514 de Q-Sentinel.

Uso (desde c:\\dev\\Sentinel con el venv activado):
    python scripts/actividad/inyectar.py
    python scripts/actividad/inyectar.py --delay 1.5   # 1.5 s entre envíos
    python scripts/actividad/inyectar.py --host 192.168.128.1
"""

import argparse
import secrets
import socket
import time
from pathlib import Path

ARCHIVO = Path(__file__).with_name("logs_actividad.txt")
HOST_DEFAULT = "127.0.0.1"
PUERTO_DEFAULT = 514
FACILITY_SEVERITY = 134   # local0.info  →  <134>


def parsear(linea: str):
    """Devuelve (hora, usuario, evento, ip) o None si la línea no es un registro."""
    s = linea.strip()
    if not s or s.startswith("#"):
        return None
    partes = [p.strip() for p in s.split("|")]
    if len(partes) != 4:
        return None
    return partes


def construir_syslog(hora: str, usuario: str, evento: str, ip: str) -> str:
    """Compone un mensaje syslog RFC3164 plausible.

    Para acciones sensibles (usuario root o IP externa) agregamos metadata
    de auditoría — session, request id, pid, severidad — que un SIEM real
    emitiría en esos casos. Eso sube la entropía del mensaje y permite que
    el detector estadístico de Sentinel (H > 5.0 bits) los marque.
    """
    fecha = time.strftime("%b %d")
    host = "corp-srv"
    app = "auth"
    base = (
        f"<{FACILITY_SEVERITY}>{fecha} {hora}:00 {host} {app}: "
        f"user={usuario} action=\"{evento}\" src={ip}"
    )
    sensible = (usuario == "root") or (not ip.startswith("192.168."))
    if sensible:
        sev = "CRIT" if usuario == "root" else "WARN"
        session = secrets.token_hex(12)
        req_id = secrets.token_hex(8)
        pid = secrets.randbelow(99999)
        base += f" sev={sev} session={session} req_id={req_id} pid={pid}"
    return base


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=HOST_DEFAULT,
                        help=f"IP del listener (default {HOST_DEFAULT})")
    parser.add_argument("--puerto", type=int, default=PUERTO_DEFAULT,
                        help=f"Puerto UDP (default {PUERTO_DEFAULT})")
    parser.add_argument("--delay", type=float, default=0.8,
                        help="Segundos entre cada envío (default 0.8)")
    args = parser.parse_args()

    if not ARCHIVO.exists():
        raise SystemExit(f"[!] No encuentro {ARCHIVO}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total = enviados = 0

    with ARCHIVO.open(encoding="utf-8") as f:
        for linea in f:
            registro = parsear(linea)
            if registro is None:
                continue
            total += 1
            hora, usuario, evento, ip = registro
            mensaje = construir_syslog(hora, usuario, evento, ip)
            sock.sendto(mensaje.encode("utf-8"), (args.host, args.puerto))
            enviados += 1
            print(f"  [{enviados:02d}] {hora}  {usuario:<8}  {evento:<32}  {ip}")
            time.sleep(args.delay)

    sock.close()
    print(f"\n[OK] {enviados}/{total} registros enviados a {args.host}:{args.puerto}")


if __name__ == "__main__":
    main()
