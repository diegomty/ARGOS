"""Honeypot de baja interacción: servicios señuelo que registran toda conexión.

Cualquier conexión a un puerto señuelo es sospechosa por definición — nadie
legítimo se conecta a un servicio falso —, así que cada "hit" es una señal de
amenaza REAL y de alta confianza, sin necesidad de puerto espejo ni de inferir
nada. Complementa la detección estadística/ML con verdad de campo.

Sigue el mismo patrón que core/flowlistener.py: listeners en hilos daemon que
emiten cada evento por un callback `on_hit`, para que el servidor lo enchufe al
pipeline (persistencia + WebSocket + Anomalías) sin que este módulo sepa nada
de Q-Sentinel.
"""

from __future__ import annotations

import socket
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

# puerto -> (nombre de servicio, banner falso o None si es binario).
# Puertos "altos" para no chocar con servicios reales de Windows ni pedir admin.
# En un despliegue dedicado se cambiarían por los reales (22, 23, 445, 3389...).
DEFAULT_DECOYS: Dict[int, Tuple[str, Optional[bytes]]] = {
    2222: ("ssh", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
    2323: ("telnet", b"\r\nUbuntu 22.04.3 LTS\r\nlogin: "),
    3388: ("rdp", None),
    4445: ("smb", None),
    8080: ("http-alt",
           b"HTTP/1.1 401 Unauthorized\r\n"
           b"Server: Apache/2.4.52 (Ubuntu)\r\n"
           b"WWW-Authenticate: Basic realm=\"Panel Admin\"\r\n\r\n"),
}

HoneypotCallback = Callable[[Dict[str, Any]], None]


class HoneypotListener:
    """Levanta un señuelo por puerto y emite cada conexión por callback."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        decoys: Optional[Dict[int, Tuple[str, Optional[bytes]]]] = None,
        timeout_s: float = 3.0,
    ) -> None:
        self.host = host
        self.decoys = decoys or DEFAULT_DECOYS
        self.timeout_s = timeout_s
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._hits = 0
        self._errors = 0

    # ---- API pública (idéntica en forma a FlowListener) ----

    def start(self, on_hit: HoneypotCallback) -> None:
        if self._threads:
            return
        for port in self.decoys:
            t = threading.Thread(
                target=self._serve,
                args=(port, on_hit),
                daemon=True,
                name=f"honeypot-{port}",
            )
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=2)
        self._threads = []

    def stats(self) -> Dict[str, Any]:
        return {"hits": self._hits, "errors": self._errors,
                "puertos": list(self.decoys)}

    # ---- Internos ----

    def _serve(self, port: int, on_hit: HoneypotCallback) -> None:
        """Bucle de escucha de UN señuelo. Corre en su propio hilo daemon."""
        service, banner = self.decoys[port]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, port))
            s.listen(5)
            # Timeout en accept() para poder revisar _stop y salir limpio.
            s.settimeout(1.0)
            print(f"[honeypot] señuelo {service} en {self.host}:{port}", flush=True)
            while not self._stop.is_set():
                try:
                    conn, addr = s.accept()
                except socket.timeout:
                    continue
                self._handle(conn, addr, port, service, banner, on_hit)
        except OSError as e:
            print(f"[honeypot] no se pudo abrir {port}: {e}", flush=True)
        finally:
            s.close()

    def _handle(self, conn, addr, port, service, banner, on_hit) -> None:
        """Atiende una conexión: manda banner, captura datos, emite el hit."""
        raw = b""
        try:
            conn.settimeout(self.timeout_s)
            if banner:
                conn.sendall(banner)
            try:
                raw = conn.recv(1024)
            except socket.timeout:
                pass
        except OSError:
            self._errors += 1
        finally:
            conn.close()

        self._hits += 1
        hit = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "src_ip": addr[0],
            "src_port": addr[1],
            "dst_port": port,
            "service": service,
            "banner_sent": banner is not None,
            "data": _safe_text(raw),
            "data_len": len(raw),
        }
        try:
            on_hit(hit)
        except Exception as e:  # nunca tumbar el hilo por el callback
            print(f"[honeypot] callback error: {e}", flush=True)


def _safe_text(raw: bytes, limit: int = 300) -> str:
    """Bytes -> texto seguro para log/JSON: decodifica, escapa saltos, trunca."""
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    return text[:limit]


# Demo standalone: `python -m core.honeypot`
if __name__ == "__main__":
    def imprimir(hit: Dict[str, Any]) -> None:
        print(f"[!] {hit['service']}:{hit['dst_port']} <- "
              f"{hit['src_ip']}:{hit['src_port']}  data={hit['data'][:80]!r}")

    hp = HoneypotListener()
    hp.start(imprimir)
    print("[honeypot] activo. Ctrl+C para salir.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hp.stop()
        print(f"\n[honeypot] detenido. stats={hp.stats()}")
