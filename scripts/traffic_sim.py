"""Generador de tráfico NORMAL: inyecta NetFlow v9 benigno al colector.

Compañero de scripts/attack_sim.py — usa el mismo template y exporter, pero
fabrica flujos que imitan la actividad cotidiana de una oficina: navegación
web, DNS, correo y transferencias internas entre departamentos. Sirve para
construir la línea base del modelo local adaptativo (la mitad "adquirida"
del híbrido) antes de demostrar que aprende.

Los flujos van entre hosts de departamentos (path por SW1) y de departamentos
hacia la zona externa (path por R1), de modo que se pintan como partículas en
el digital twin igual que el tráfico real del lab.

Uso (con el servidor corriendo):
    python -m scripts.traffic_sim --flows 300
    python -m scripts.traffic_sim --flows 300 --rate 50

Para la línea base local hacen falta MIN_FLOWS flujos en la ventana (ver
ml/local.py). 300 da margen de sobra.
"""

from __future__ import annotations

import argparse
import random
import time

from scripts.attack_sim import Exporter

# Hosts internos del lab (ver topology.yaml). El tráfico normal ocurre
# entre estos y hacia la web externa.
DEPT_HOSTS = [
    "10.10.10.10",  # PC-FIN-01
    "10.10.20.10",  # PC-RH-01
    "10.10.30.10",  # PC-TI-01
    "10.10.40.10",  # PC-ID-01
    "10.10.50.10",  # PC-PR-01
    "10.10.60.10",  # PC-VE-01
]
# Servidores web "externos" legítimos (zona 10.0.0.0/24, distintos del atacante).
WEB_SERVERS = ["10.0.0.10", "10.0.0.20", "10.0.0.30", "10.0.0.50"]


def _web_browse(src: str) -> dict:
    """Sesión HTTPS típica: decenas de paquetes, KBs, segundos."""
    pkts = random.randint(12, 80)
    return {
        "src_ip": src, "dst_ip": random.choice(WEB_SERVERS),
        "src_port": random.randint(40000, 60000),
        "dst_port": random.choice([443, 443, 443, 80]),
        "protocol_num": 6, "packets": pkts,
        "bytes": pkts * random.randint(400, 1200),
        "duration_ms": random.randint(200, 8000),
    }


def _dns_query(src: str) -> dict:
    """Consulta DNS: 2 paquetes, pocos cientos de bytes, milisegundos."""
    return {
        "src_ip": src, "dst_ip": "10.0.0.10",
        "src_port": random.randint(40000, 60000), "dst_port": 53,
        "protocol_num": 17, "packets": 2,
        "bytes": random.randint(120, 400),
        "duration_ms": random.randint(1, 40),
    }


def _internal_share(src: str) -> dict:
    """Transferencia interna SMB entre departamentos (host→host por SW1)."""
    dst = random.choice([h for h in DEPT_HOSTS if h != src])
    pkts = random.randint(20, 200)
    return {
        "src_ip": src, "dst_ip": dst,
        "src_port": random.randint(40000, 60000), "dst_port": 445,
        "protocol_num": 6, "packets": pkts,
        "bytes": pkts * random.randint(500, 1400),
        "duration_ms": random.randint(300, 12000),
    }


def _email(src: str) -> dict:
    """Envío/recepción de correo (SMTP/IMAPS)."""
    pkts = random.randint(10, 60)
    return {
        "src_ip": src, "dst_ip": "10.0.0.20",
        "src_port": random.randint(40000, 60000),
        "dst_port": random.choice([587, 993]),
        "protocol_num": 6, "packets": pkts,
        "bytes": pkts * random.randint(300, 900),
        "duration_ms": random.randint(150, 5000),
    }


# Mezcla ponderada: la navegación y el DNS dominan el día a día.
MIX = [(_web_browse, 0.45), (_dns_query, 0.30), (_internal_share, 0.15), (_email, 0.10)]


def _gen_one() -> dict:
    src = random.choice(DEPT_HOSTS)
    r = random.random()
    cum = 0.0
    for fn, w in MIX:
        cum += w
        if r <= cum:
            return fn(src)
    return _web_browse(src)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generador de tráfico normal NetFlow v9")
    ap.add_argument("--flows", type=int, default=300, help="cuántos flujos benignos enviar")
    ap.add_argument("--rate", type=int, default=60, help="flujos por segundo (aprox)")
    args = ap.parse_args()

    exp = Exporter()
    print(f"[*] Enviando template v9 a {exp and '127.0.0.1:2055'}...")
    exp.send_template()

    flows = [_gen_one() for _ in range(args.flows)]
    gap = max(0.05, 8 / args.rate)  # batch de 8 → pausa para acercarse al rate
    print(f"[*] Inyectando {len(flows)} flujos normales (~{args.rate}/s)...")
    exp.send(flows, batch=8, gap=gap)

    print(f"\n[OK] {len(flows)} flujos normales inyectados.")
    print("     Para construir la línea base local:")
    print("       1) reinicia el servidor (re-entrena al arrancar), o")
    print("       2) espera al re-entrenamiento periódico.")


if __name__ == "__main__":
    main()
