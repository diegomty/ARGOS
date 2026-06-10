"""Simulador de ataque: inyecta NetFlow v9 real al colector de Q-Sentinel.

Fabrica datagramas NetFlow v9 (RFC 3954) idénticos a los que exportaría el
Cisco 7200 y los envía a UDP/2055, ejerciendo el pipeline COMPLETO y real:

    parser v9 → dedupe 5-tupla → featurización → detector híbrido → WS → viz

A diferencia de /api/test-flow (que se salta el parser y fuerza el veredicto),
aquí el detector decide de verdad: si una partícula sale roja, es porque el
modelo heredado o el local marcaron ese flujo.

Escenarios (todos contra el lab de topology.yaml):
  portscan    — barrido de puertos del atacante (10.0.0.2) a PC-TI-01
  ddos        — botnet externa (10.0.0.0/24) inundando PC-TI-01:80
  bruteforce  — fuerza bruta SSH del atacante a PC-TI-01:22
  exfil       — exfiltración de 50 MB de PC-TI-01 al atacante:4444
  all         — los cuatro en secuencia, como un ataque multi-etapa

Uso (con el servidor corriendo):
    python -m scripts.attack_sim --attack all
    python -m scripts.attack_sim --attack portscan --target 10.10.30.10

NOTA: no toca la red real; solo habla con el colector local. Es una
herramienta de validación del detector, no un generador de tráfico ofensivo.
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import time

COLLECTOR = ("127.0.0.1", 2055)

# Atacante y víctima por defecto (ver topology.yaml).
ATTACKER_IP = "10.0.0.2"
DEFAULT_TARGET = "10.10.30.10"  # PC-TI-01 (dept crítico)
EXTERNAL_SUBNET = "10.0.0."     # /24 de la zona externa para la botnet

# Template v9 que definimos: orden de campos (type, length) que el parser
# de core/flowlistener.py sabe decodificar.
TEMPLATE_ID = 256
TEMPLATE_FIELDS = [
    (1, 4),   # IN_BYTES
    (2, 4),   # IN_PKTS
    (4, 1),   # PROTOCOL
    (7, 2),   # L4_SRC_PORT
    (8, 4),   # IPV4_SRC_ADDR
    (11, 2),  # L4_DST_PORT
    (12, 4),  # IPV4_DST_ADDR
    (22, 4),  # FIRST_SWITCHED (ms de uptime)
    (21, 4),  # LAST_SWITCHED  (ms de uptime)
]

_boot = time.time()


def _uptime_ms() -> int:
    return int((time.time() - _boot) * 1000) + 100_000


def build_template_packet(seq: int) -> bytes:
    """Datagrama con un único Template FlowSet (id=0)."""
    fields = b"".join(struct.pack("!HH", t, l) for t, l in TEMPLATE_FIELDS)
    content = struct.pack("!HH", TEMPLATE_ID, len(TEMPLATE_FIELDS)) + fields
    flowset = struct.pack("!HH", 0, 4 + len(content)) + content
    header = struct.pack("!HHIIII", 9, 1, _uptime_ms(), int(time.time()), seq, 1)
    return header + flowset


def _pack_record(flow: dict) -> bytes:
    last = _uptime_ms()
    first = last - int(flow["duration_ms"])
    return (
        struct.pack("!I", flow["bytes"])
        + struct.pack("!I", flow["packets"])
        + struct.pack("!B", flow["protocol_num"])
        + struct.pack("!H", flow["src_port"])
        + socket.inet_aton(flow["src_ip"])
        + struct.pack("!H", flow["dst_port"])
        + socket.inet_aton(flow["dst_ip"])
        + struct.pack("!I", first & 0xFFFFFFFF)
        + struct.pack("!I", last & 0xFFFFFFFF)
    )


def build_data_packet(flows: list[dict], seq: int) -> bytes:
    """Datagrama con un Data FlowSet (id=TEMPLATE_ID) y N records."""
    content = b"".join(_pack_record(f) for f in flows)
    flowset = struct.pack("!HH", TEMPLATE_ID, 4 + len(content)) + content
    header = struct.pack("!HHIIII", 9, len(flows), _uptime_ms(), int(time.time()), seq, 1)
    return header + flowset


class Exporter:
    """Envía datagramas al colector con secuencia y template inicial."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.seq = 0

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def send_template(self) -> None:
        self.sock.sendto(build_template_packet(self._next_seq()), COLLECTOR)
        time.sleep(0.2)  # deja que el colector registre el template primero

    def send(self, flows: list[dict], batch: int = 8, gap: float = 0.25) -> None:
        """Trocea en datagramas de `batch` flujos con pausa `gap` entre ellos."""
        for i in range(0, len(flows), batch):
            chunk = flows[i:i + batch]
            self.sock.sendto(build_data_packet(chunk, self._next_seq()), COLLECTOR)
            time.sleep(gap)


# --- Generadores de escenarios → listas de flujos ---

# Valores calibrados contra la distribución real de cada ataque en CICIDS2017
# (medianas/percentiles medidos sobre datasets/cicids_attacks.npz). Replicar
# la firma per-flow real es lo que hace que el modelo heredado los reconozca.


def gen_portscan(target: str, n: int = 60) -> list[dict]:
    """Barrido SYN estilo nmap: 2 paquetes, ~6 bytes, duración nula.

    Lo distintivo no son los puertos "comunes" sino sondas vacías a puertos
    repartidos por todo el rango (mediana real ≈ 3784). Esos 6 bytes en 2
    paquetes son la firma que aprendió el modelo."""
    flows = []
    for _ in range(n):
        flows.append({
            "src_ip": ATTACKER_IP, "dst_ip": target,
            "src_port": random.randint(40000, 60000),
            "dst_port": random.randint(1, 30000),
            "protocol_num": 6, "packets": 2,
            "bytes": random.randint(6, 12),
            "duration_ms": 0,
        })
    return flows


def gen_ddos(target: str, n: int = 80) -> list[dict]:
    """Botnet externa inundando :80 — ráfagas HTTP cortas desde muchos orígenes."""
    flows = []
    for _ in range(n):
        src = EXTERNAL_SUBNET + str(random.randint(3, 254))
        flows.append({
            "src_ip": src, "dst_ip": target,
            "src_port": random.randint(1024, 65535), "dst_port": 80,
            "protocol_num": 6, "packets": random.randint(4, 13),
            "bytes": random.randint(8000, 12000),
            "duration_ms": random.randint(70, 3000),
        })
    return flows


def gen_bruteforce(target: str, n: int = 50) -> list[dict]:
    """Fuerza bruta SSH a :22 — sesiones de ~26 paquetes y ~3 KB (perfil Patator)."""
    flows = []
    for _ in range(n):
        flows.append({
            "src_ip": ATTACKER_IP, "dst_ip": target,
            "src_port": random.randint(40000, 60000), "dst_port": 22,
            "protocol_num": 6, "packets": random.randint(8, 54),
            "bytes": random.randint(1500, 4700),
            "duration_ms": random.randint(100, 13000),
        })
    return flows


def gen_exfil(target: str, n: int = 6) -> list[dict]:
    """Exfiltración: transferencias enormes del interior al atacante:4444.

    Este es el escenario que el modelo heredado NO conoce (no existe en
    CICIDS) — sirve para demostrar que el modelo local adaptativo es quien
    debe atraparlo una vez que tiene línea base.
    """
    flows = []
    for _ in range(n):
        flows.append({
            "src_ip": target, "dst_ip": ATTACKER_IP,
            "src_port": random.randint(40000, 60000), "dst_port": 4444,
            "protocol_num": 6, "packets": random.randint(30000, 60000),
            "bytes": random.randint(40_000_000, 80_000_000),
            "duration_ms": random.randint(45000, 90000),
        })
    return flows


SCENARIOS = {
    "portscan": gen_portscan,
    "ddos": gen_ddos,
    "bruteforce": gen_bruteforce,
    "exfil": gen_exfil,
}


def run_scenario(exp: Exporter, name: str, target: str) -> None:
    flows = SCENARIOS[name](target)
    print(f"  [>] {name:11s} → {len(flows):>3} flujos hacia {target}")
    exp.send(flows)


def main() -> None:
    ap = argparse.ArgumentParser(description="Simulador NetFlow v9 de ataque para Q-Sentinel")
    ap.add_argument("--attack", choices=[*SCENARIOS, "all"], default="all")
    ap.add_argument("--target", default=DEFAULT_TARGET, help="IP víctima (host de un depto)")
    args = ap.parse_args()

    exp = Exporter()
    print(f"[*] Colector destino: {COLLECTOR[0]}:{COLLECTOR[1]}")
    print("[*] Enviando template v9...")
    exp.send_template()

    if args.attack == "all":
        print("[*] Ataque multi-etapa: recon → DDoS → fuerza bruta → exfiltración\n")
        for name in ["portscan", "ddos", "bruteforce", "exfil"]:
            run_scenario(exp, name, args.target)
            time.sleep(1.0)
    else:
        run_scenario(exp, args.attack, args.target)

    print("\n[OK] Inyección completa.")
    print("     Revisa el dashboard (partículas rojas) y:")
    print("       Invoke-RestMethod http://localhost:8000/api/ml | ConvertTo-Json -Depth 4")


if __name__ == "__main__":
    main()
