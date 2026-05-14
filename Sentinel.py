"""Q-Sentinel — listener UDP/syslog con respuesta autónoma.

Uso:
    python Sentinel.py

El listener emite un `SentinelEvent` por cada datagrama recibido a través
de la callback `on_event`. La callback por defecto imprime en consola; el
servidor FastAPI de la Fase E inyectará una callback que difunde por
WebSocket.
"""

import socket
from datetime import datetime
from typing import Callable, Optional

from core import config
from core.analysis import (
    calcular_entropia,
    es_confiable,
    hash_sha3,
    identificar_atacante,
)
from core.events import SentinelEvent
from core.responder import bloquear_ip_en_router


EventCallback = Callable[[SentinelEvent], None]


def _imprimir_evento(ev: SentinelEvent) -> None:
    """Callback CLI por defecto — replica la salida del Sentinel original."""
    if not ev.is_anomaly:
        return
    print(
        f"\n[{ev.timestamp}] 🚨 ANOMALÍA: H={ev.entropy:.2f} bits  "
        f"SHA3={ev.sha3[:16]}…",
        flush=True,
    )
    if ev.plan == "B":
        print(
            f"[!] Origen oculto (UNKNOWN). Plan B: bloqueando "
            f"{ev.attacker_ip}",
            flush=True,
        )
    elif ev.plan == "NONE":
        print("[?] No se pudo identificar al atacante.", flush=True)
    for linea in ev.response_log:
        print(linea, flush=True)


def _construir_evento(mensaje: str, source_ip: str) -> SentinelEvent:
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    h_valor = calcular_entropia(mensaje)
    confiable = es_confiable(mensaje)
    es_anomalia = (
        not confiable
        and h_valor > config.UMBRAL_ENTROPIA
        and config.MI_PC_IP not in mensaje
    )
    return SentinelEvent(
        timestamp=ahora,
        raw_message=mensaje,
        source_ip=source_ip,
        entropy=h_valor,
        sha3=hash_sha3(mensaje),
        is_trusted=confiable,
        is_anomaly=es_anomalia,
    )


def iniciar_q_sentinel(on_event: Optional[EventCallback] = None) -> None:
    """Bucle principal del listener. Bloqueante.

    `on_event` se invoca para CADA datagrama (incluyendo los benignos),
    para que la visualización 3D pueda animarse con tráfico normal y no
    solo en alertas.
    """
    callback = on_event or _imprimir_evento

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.bind((config.IP_ESCUCHA, config.PUERTO_SYSLOG))
        print("[*] Q-Sentinel v1.4.0 - Inmunidad Digital Activa", flush=True)

        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue

            mensaje = data.decode("utf-8", errors="ignore").strip()
            evento = _construir_evento(mensaje, addr[0])

            if evento.is_anomaly:
                ip, plan = identificar_atacante(mensaje)
                evento.attacker_ip = ip
                evento.plan = plan
                if ip:
                    evento.blocked = bloquear_ip_en_router(
                        ip,
                        on_log=evento.response_log.append,
                    )

            callback(evento)
    except KeyboardInterrupt:
        print("\n[!] Sistema apagado.")
    finally:
        sock.close()


if __name__ == "__main__":
    iniciar_q_sentinel()
