"""Sensor de captura pasiva: sniffer que produce flujos reales de la red.

Captura paquetes de una interfaz con Scapy, los agrega por 5-tupla y emite
cada flujo terminado por un callback `on_flow` — con la MISMA forma que produce
core/flowlistener.py (NetFlow), para que enchufe al pipeline sin cambios.

Así Q-Sentinel deja de depender de que un router exporte NetFlow: puede
descubrir y monitorear cualquier red observando su tráfico directamente.

Mismo patrón que FlowListener/HoneypotListener: hilos daemon + callback. Usa
`AsyncSniffer` de Scapy (captura en su propio hilo, con stop() limpio).

Requiere privilegios de administrador y Npcap (Windows) o libpcap.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from scapy.all import AsyncSniffer, IP, TCP, UDP, DHCP, BOOTP, DNS, DNSRR

PROTOCOLOS: Dict[int, str] = {1: "icmp", 6: "tcp", 17: "udp", 2: "igmp", 47: "gre"}

FlowCallback = Callable[[Dict[str, Any]], None]
# on_identity(ip, mac, hostname, source): un dispositivo se dio a conocer.
IdentityCallback = Callable[[str, Optional[str], Optional[str], str], None]
# on_alert(alert_dict): se detectó un ataque por TASA (p. ej. un flood DoS).
AlertCallback = Callable[[Dict[str, Any]], None]

# --- Detector de flood/DoS por tasa ---
# Un flood se mide por (origen -> destino:puerto-destino), IGNORANDO el puerto
# de origen: hping3 y muchos DoS lo aleatorizan en cada paquete, así que el
# ataque se parte en miles de flujos de 1 paquete. Agregando por ese trío, la
# tormenta reaparece como una tasa altísima de paquetes/seg a un mismo objetivo.
#
# Para NO confundir un flood con tráfico legítimo de alta tasa (video, QUIC,
# descargas) se aplican dos firmas: en TCP solo cuentan los SYN puros (un SYN
# flood), y en UDP/otros se exige que los paquetes sean diminutos (un flood usa
# paquetes chicos; el streaming usa paquetes grandes ~1200B).
FLOOD_WINDOW = 1.0          # ventana de medición (s)
FLOOD_MIN_PPS = 400         # paquetes/seg desde un origen a un destino:puerto
FLOOD_MIN_PACKETS = 200     # mínimo absoluto en la ventana (evita picos triviales)
FLOOD_MAX_AVG_BYTES = 150   # tamaño medio máximo (UDP/otros): filtra streaming/QUIC
FLOOD_COOLDOWN = 10.0       # no repetir la alerta del mismo flood por este tiempo
# Puertos/destinos ruidosos por diseño (broadcast/descubrimiento): se ignoran.
FLOOD_IGNORE_PORTS = {53, 67, 68, 137, 138, 1900, 5353, 5355}


def _mac_from_chaddr(chaddr: Any) -> Optional[str]:
    """MAC del cliente DHCP (campo chaddr de BOOTP) en formato AA:BB:CC:DD:EE:FF."""
    try:
        raw = bytes(chaddr)[:6]
        if len(raw) < 6 or raw == b"\x00" * 6:
            return None
        return ":".join(f"{b:02X}" for b in raw)
    except Exception:
        return None


def _rr_name(name: Any) -> Optional[str]:
    """Nombre de un registro DNS/mDNS a texto, sin el punto final."""
    try:
        s = name.decode(errors="ignore") if isinstance(name, (bytes, bytearray)) else str(name)
        return s.rstrip(".") or None
    except Exception:
        return None


def _extraer(paquete) -> Optional[tuple]:
    """Paquete Scapy -> (clave 5-tupla, protocol, bytes). None si no es IPv4."""
    if IP not in paquete:
        return None
    ip = paquete[IP]
    proto_num = ip.proto
    sport = dport = 0
    if TCP in paquete:
        sport, dport = paquete[TCP].sport, paquete[TCP].dport
    elif UDP in paquete:
        sport, dport = paquete[UDP].sport, paquete[UDP].dport
    clave = (ip.src, ip.dst, sport, dport, proto_num)
    return clave, PROTOCOLOS.get(proto_num, f"proto-{proto_num}"), len(paquete)


def _to_flow(clave: tuple, fl: dict) -> Dict[str, Any]:
    """Flujo interno -> dict con la forma del pipeline (igual que FlowListener)."""
    src, dst, sp, dp, proto_num = clave
    return {
        "src_ip": src, "dst_ip": dst,
        "src_port": sp, "dst_port": dp,
        "protocol_num": proto_num, "protocol": fl["protocol"],
        "packets": fl["packets"], "bytes": fl["bytes"],
        "duration_ms": int((fl["last"] - fl["first"]) * 1000),
        "exporter": "sensor-local",
    }


class PassiveSensor:
    """Captura pasiva de tráfico y emisión de flujos por callback."""

    def __init__(
        self,
        iface: Optional[str] = None,
        flush_interval: float = 5.0,
        inactive_timeout: float = 60.0,   # ventana amplia: evita fragmentar una
        # conexión persistente (Steam, streaming) en decenas de flujos separados.
    ) -> None:
        self.iface = iface
        self.flush_interval = flush_interval
        self.inactive_timeout = inactive_timeout
        self._flows: Dict[tuple, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sniffer: Optional[AsyncSniffer] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._packets = 0
        self._emitted = 0
        self._on_identity: Optional[IdentityCallback] = None
        self._dhcp_names: Dict[str, str] = {}   # mac -> hostname (visto en DHCP)
        self._on_alert: Optional[AlertCallback] = None
        self._flood: Dict[tuple, dict] = {}     # (src,dst,dport,proto) -> ventana

    # ---- API pública (misma forma que FlowListener) ----

    def start(self, on_flow: FlowCallback,
              on_identity: Optional[IdentityCallback] = None,
              on_alert: Optional[AlertCallback] = None) -> None:
        if self._sniffer is not None:
            return
        self._on_identity = on_identity
        self._on_alert = on_alert
        # AsyncSniffer captura en su propio hilo; filtramos a IP en la captura.
        self._sniffer = AsyncSniffer(prn=self._on_packet, store=False,
                                     filter="ip", iface=self.iface)
        self._sniffer.start()
        self._flush_thread = threading.Thread(
            target=self._flush_loop, args=(on_flow,),
            daemon=True, name="sensor-flush",
        )
        self._flush_thread.start()
        print(f"[sensor] captura pasiva activa (iface={self.iface or 'default'})",
              flush=True)

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=3)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            activos = len(self._flows)
        return {"packets": self._packets, "emitted": self._emitted, "active": activos}

    # ---- Internos ----

    def _on_packet(self, paquete) -> None:
        """Callback de captura: acumula el paquete en su flujo (bajo lock)."""
        datos = _extraer(paquete)
        if datos is None:
            return
        clave, proto, nbytes = datos
        t = float(paquete.time)
        # ¿SYN "puro"? (SYN sí, ACK no) — firma de SYN flood; distingue de los
        # ACK de una descarga normal, que son igual de chicos pero llevan ACK.
        is_syn = False
        if clave[4] == 6 and TCP in paquete:
            try:
                f = int(paquete[TCP].flags)
                is_syn = (f & 0x02) != 0 and (f & 0x10) == 0
            except Exception:
                pass
        alert = None
        with self._lock:
            self._packets += 1
            fl = self._flows.get(clave)
            if fl is None:
                self._flows[clave] = {"protocol": proto, "packets": 1,
                                      "bytes": nbytes, "first": t, "last": t}
            else:
                fl["packets"] += 1
                fl["bytes"] += nbytes
                fl["last"] = t
            alert = self._track_flood(clave, t, nbytes, is_syn)
        # Callbacks fuera del lock (pueden tocar storage / red). Best-effort.
        if alert is not None:
            self._emit_alert(alert)
        if self._on_identity is not None:
            self._extraer_identidad(paquete)

    # ---- Detector de flood/DoS por tasa ----

    @staticmethod
    def _is_noisy(dst: str, dport: int) -> bool:
        """True si el destino es broadcast/multicast o un puerto de descubrimiento
        (SSDP, mDNS, DHCP…): su ráfaga normal no es un ataque."""
        if dst.startswith(("224.", "239.", "255.")) or dst.endswith(".255"):
            return True
        return dport in FLOOD_IGNORE_PORTS

    def _track_flood(self, clave: tuple, t: float, nbytes: int,
                     is_syn: bool) -> Optional[Dict[str, Any]]:
        """Cuenta paquetes por (origen, destino, puerto-destino) en ventanas de
        1 s y decide si es un ATAQUE (no tráfico legítimo de alta tasa):
          * TCP: solo cuentan los SYN puros (firma de SYN flood); los ACK de una
            descarga —chicos pero con ACK— no entran.
          * UDP/otros: además exige paquetes DIMINUTOS (streaming/QUIC usa ~1200B
            y así queda excluido).
        Devuelve una alerta (una vez por ventana, con enfriamiento) o None."""
        if self._on_alert is None:
            return None
        src, dst, _sport, dport, proto_num = clave
        if self._is_noisy(dst, dport):
            return None
        if proto_num == 6 and not is_syn:
            return None    # TCP que no es SYN puro: no es SYN flood
        key = (src, dst, dport, proto_num)
        fr = self._flood.get(key)
        if fr is None:
            self._flood[key] = {"count": 1, "bytes": nbytes, "start": t, "cooldown": 0.0}
            return None
        fr["count"] += 1
        fr["bytes"] += nbytes
        elapsed = t - fr["start"]
        if elapsed < FLOOD_WINDOW:
            return None
        pps = fr["count"] / elapsed if elapsed > 0 else fr["count"]
        avg = fr["bytes"] / max(fr["count"], 1)
        ataque = (fr["count"] >= FLOOD_MIN_PACKETS and pps >= FLOOD_MIN_PPS
                  and t >= fr["cooldown"])
        if proto_num != 6 and avg > FLOOD_MAX_AVG_BYTES:
            ataque = False    # paquetes grandes = streaming legítimo, no flood
        alert = None
        if ataque:
            fr["cooldown"] = t + FLOOD_COOLDOWN
            alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "src_ip": src, "dst_ip": dst, "dst_port": dport,
                "protocol": PROTOCOLOS.get(proto_num, f"proto-{proto_num}"),
                "pps": int(pps), "packets": fr["count"], "avg_bytes": int(avg),
                "kind": "dos-flood",
            }
        fr["count"] = 0        # reinicia la ventana
        fr["bytes"] = 0
        fr["start"] = t
        return alert

    def _emit_alert(self, alert: Dict[str, Any]) -> None:
        try:
            self._on_alert(alert)
        except Exception as e:
            print(f"[sensor] on_alert error: {e}", flush=True)

    # ---- Identidad de dispositivos (DHCP / mDNS) ----

    def _extraer_identidad(self, paquete) -> None:
        """Busca nombres de dispositivo en DHCP (opción 12) y mDNS (.local)."""
        try:
            if UDP not in paquete:
                return
            sport, dport = paquete[UDP].sport, paquete[UDP].dport
            if 67 in (sport, dport) or 68 in (sport, dport):
                self._identidad_dhcp(paquete)
            elif sport == 5353 or dport == 5353:
                self._identidad_mdns(paquete)
        except Exception:
            pass  # un parseo raro nunca debe romper la captura

    def _identidad_dhcp(self, paquete) -> None:
        """DHCP: el equipo anuncia su nombre (opción 12) y su MAC (chaddr)."""
        if BOOTP not in paquete:
            return
        bootp = paquete[BOOTP]
        mac = _mac_from_chaddr(bootp.chaddr)
        hostname = None
        if DHCP in paquete:
            for opt in paquete[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    val = opt[1]
                    hostname = (val.decode(errors="ignore")
                                if isinstance(val, (bytes, bytearray)) else str(val))
                    break
        if hostname and mac:
            self._dhcp_names[mac] = hostname   # recordamos para cruzarlo con la IP
        # IP conocida: ciaddr (renovación) o yiaddr (la que asigna el servidor).
        ip = None
        for cand in (bootp.ciaddr, bootp.yiaddr):
            if cand and cand != "0.0.0.0":
                ip = cand
                break
        if ip is None:
            return
        self._emitir_identidad(ip, mac, hostname or self._dhcp_names.get(mac), "dhcp")

    def _identidad_mdns(self, paquete) -> None:
        """mDNS: los registros A mapean un nombre `.local` a la IP del equipo."""
        if DNS not in paquete:
            return
        dns = paquete[DNS]
        rr, vistos = dns.an, 0
        while rr is not None and vistos < (dns.ancount or 0):
            if getattr(rr, "type", None) == 1:   # registro A (nombre -> IPv4)
                nombre = _rr_name(rr.rrname)
                ip = getattr(rr, "rdata", None)
                if nombre and ip:
                    if nombre.endswith(".local"):
                        nombre = nombre[:-6]
                    self._emitir_identidad(str(ip), None, nombre, "mdns")
            nxt = getattr(rr, "payload", None)
            rr = nxt if isinstance(nxt, DNSRR) else None
            vistos += 1

    def _emitir_identidad(self, ip: str, mac: Optional[str],
                          hostname: Optional[str], source: str) -> None:
        if self._on_identity is None or not ip:
            return
        try:
            self._on_identity(ip, mac, hostname, source)
        except Exception as e:
            print(f"[sensor] on_identity error: {e}", flush=True)

    def _flush_loop(self, on_flow: FlowCallback) -> None:
        """Cada `flush_interval` emite los flujos terminados."""
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            self._flush(on_flow)
        self._flush(on_flow, forzar=True)  # emite lo que quede al parar

    def _flush(self, on_flow: FlowCallback, forzar: bool = False) -> None:
        ahora = time.time()
        with self._lock:
            terminados = [k for k, f in self._flows.items()
                          if forzar or (ahora - f["last"]) > self.inactive_timeout]
            listos = [(k, self._flows.pop(k)) for k in terminados]
            # Poda del rastreador de flood: descarta ventanas ya inactivas.
            self._flood = {k: v for k, v in self._flood.items()
                           if ahora - v["start"] < 60}
        for clave, fl in listos:
            self._emitted += 1
            try:
                on_flow(_to_flow(clave, fl))
            except Exception as e:
                print(f"[sensor] callback error: {e}", flush=True)


# Demo standalone: `python -m core.sensor`  (como administrador)
if __name__ == "__main__":
    def imprimir(flujo: Dict[str, Any]) -> None:
        print(f"[flujo] {flujo['protocol']:5} "
              f"{flujo['src_ip']}:{flujo['src_port']} -> "
              f"{flujo['dst_ip']}:{flujo['dst_port']}  "
              f"{flujo['packets']} paq · {flujo['bytes']} B · {flujo['duration_ms']} ms")

    sensor = PassiveSensor(inactive_timeout=8.0)
    sensor.start(imprimir)
    print("[sensor] activo. Ctrl+C para salir.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sensor.stop()
        print(f"\n[sensor] detenido. stats={sensor.stats()}")
