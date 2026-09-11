"""Servidor OBJETIVO para pruebas de estrés/DoS CONTROLADAS en tu propia red.

Levanta un servicio HTTP mínimo que responde 200 OK y registra el RITMO de
conexiones (total y por segundo), para ver en vivo cómo una herramienta de
estrés lo golpea y cómo Q-Sentinel lo detecta. No ataca a nadie: solo escucha,
responde y cuenta. Úsalo ÚNICAMENTE contra infraestructura que te pertenece
(tu PC, tu laboratorio) y con autorización.

Uso:
    python scripts/dos_target.py            # puerto 80 (requiere admin en Windows)
    python scripts/dos_target.py 8888       # puerto alto (sin admin)

Ctrl+C para detener y ver el resumen.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 80
BODY = b"Q-SENTINEL target OK\n"
RESP = (b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Connection: close\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\n\r\n" + BODY)

# Contadores aproximados (bajo el GIL; suficiente para un medidor de ritmo).
_total = 0
_bytes = 0
_stop = threading.Event()


def _handle(conn: socket.socket) -> None:
    """Atiende una conexión: lee la petición, responde 200 OK y cuenta."""
    global _total, _bytes
    try:
        conn.settimeout(1.0)
        try:
            data = conn.recv(2048)
            _bytes += len(data)
        except Exception:
            pass
        try:
            conn.sendall(RESP)
        except Exception:
            pass
    finally:
        _total += 1
        try:
            conn.close()
        except Exception:
            pass


def _stats() -> None:
    """Imprime cada segundo el total y el ritmo de conexiones (ataque en vivo)."""
    prev = 0
    while not _stop.is_set():
        time.sleep(1.0)
        now = _total
        rate = now - prev
        prev = now
        marca = "  <<< ATAQUE" if rate > 50 else ""
        print(f"[objetivo] conexiones: {now:>9}  ·  ritmo: {rate:>7}/s  ·  "
              f"datos: {_bytes/1e6:6.1f} MB{marca}", flush=True)


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", PORT))
    except PermissionError:
        print(f"[objetivo] sin permiso para el puerto {PORT}. Ejecútalo como "
              f"administrador, o usa un puerto alto:\n"
              f"    python scripts/dos_target.py 8888")
        return
    except OSError as e:
        print(f"[objetivo] no se pudo abrir el puerto {PORT}: {e}")
        return
    srv.listen(1024)
    srv.settimeout(1.0)   # accept con timeout -> Ctrl+C responde en Windows
    print(f"[objetivo] escuchando en 0.0.0.0:{PORT} (HTTP) · Ctrl+C para parar",
          flush=True)
    threading.Thread(target=_stats, daemon=True).start()
    pool = ThreadPoolExecutor(max_workers=256)
    try:
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            pool.submit(_handle, conn)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()
        srv.close()
        print(f"\n[objetivo] detenido. total conexiones: {_total} · "
              f"datos recibidos: {_bytes/1e6:.2f} MB")


if __name__ == "__main__":
    main()
