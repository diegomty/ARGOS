"""Listener UDP NetFlow v9 con parser propio.

Implementación mínima del RFC 3954 enfocada en flujos IPv4 (los que
exporta IOS 15 en el 7200). No usamos librería externa porque las
disponibles en PyPI tienen incompatibilidades con la salida de Cisco.

Diseño:
  * Listener corre en thread daemon, mismo patrón que el syslog.
  * Templates v9 se persisten por (exporter_addr, source_id, template_id)
    porque cada exporter puede usar IDs solapados.
  * Se ignoran flowsets cuyo template aún no llegó (el primer paquete
    suele ser data sin template — se reciben en orden cuando IOS reenvía).

Campos NetFlow v9 que usamos (subset; otros se almacenan crudos para debug):
  1  IN_BYTES        2  IN_PKTS         4  PROTOCOL
  7  L4_SRC_PORT     8  IPV4_SRC_ADDR   11 L4_DST_PORT
  12 IPV4_DST_ADDR   21 LAST_SWITCHED   22 FIRST_SWITCHED
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple


PROTOCOL_NAMES: Dict[int, str] = {
    1:  "icmp",
    6:  "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    89: "ospf",
}

# NetFlow v9 field types (RFC 3954) — solo los que parseamos a tipo nativo.
FIELD_NAMES: Dict[int, str] = {
    1:  "IN_BYTES",
    2:  "IN_PKTS",
    4:  "PROTOCOL",
    5:  "TOS",
    6:  "TCP_FLAGS",
    7:  "L4_SRC_PORT",
    8:  "IPV4_SRC_ADDR",
    9:  "SRC_MASK",
    10: "INPUT_SNMP",
    11: "L4_DST_PORT",
    12: "IPV4_DST_ADDR",
    13: "DST_MASK",
    14: "OUTPUT_SNMP",
    15: "IPV4_NEXT_HOP",
    21: "LAST_SWITCHED",
    22: "FIRST_SWITCHED",
    60: "IP_PROTOCOL_VERSION",
    61: "DIRECTION",
}

IPV4_FIELDS = {8, 12, 15}


FlowCallback = Callable[[Dict[str, Any]], None]


class FlowListener:
    """Captura NetFlow v9 y emite flujos normalizados.

    Como Cisco IOS exporta cada paquete dos veces cuando hay
    `ip flow ingress` Y `ip flow egress` en subifs distintos del path,
    deduplicamos por 5-tupla dentro de `dedupe_window_s` segundos.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2055,
        dedupe_window_s: float = 3.0,
    ) -> None:
        self.host = host
        self.port = port
        self.dedupe_window_s = dedupe_window_s
        # key: (exporter_ip, source_id, template_id) → list[(field_type, field_length)]
        self._templates: Dict[Tuple[str, int, int], List[Tuple[int, int]]] = {}
        # LRU de 5-tuplas vistas recientemente para dedupe
        self._recent: "OrderedDict[Tuple, float]" = OrderedDict()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._packets_seen = 0
        self._flowsets_seen = 0
        self._templates_seen = 0
        self._flows_seen = 0
        self._flows_emitted = 0
        self._parse_errors = 0

    # ---- API pública ----

    def start(self, on_flow: FlowCallback) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop,
            args=(on_flow,),
            daemon=True,
            name="netflow-listener",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    def stats(self) -> Dict[str, int]:
        return {
            "packets": self._packets_seen,
            "flowsets": self._flowsets_seen,
            "templates": self._templates_seen,
            "flows": self._flows_seen,
            "emitted": self._flows_emitted,
            "parse_errors": self._parse_errors,
        }

    def _is_duplicate(self, f: Dict[str, Any]) -> bool:
        """Devuelve True si la 5-tupla se vio dentro de la ventana de dedupe."""
        key = (f["src_ip"], f["dst_ip"], f["src_port"], f["dst_port"], f["protocol_num"])
        now = time.time()
        last = self._recent.get(key)
        if last is not None and (now - last) < self.dedupe_window_s:
            self._recent.move_to_end(key)
            self._recent[key] = now
            return True
        # Limpieza ocasional: cap de 1024 entradas + purga de obsoletas.
        self._recent[key] = now
        self._recent.move_to_end(key)
        if len(self._recent) > 1024:
            cutoff = now - self.dedupe_window_s * 4
            for k in list(self._recent):
                if self._recent[k] < cutoff:
                    del self._recent[k]
                else:
                    break
        return False

    # ---- Internals ----

    def _loop(self, on_flow: FlowCallback) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.bind((self.host, self.port))
            print(f"[netflow] listener UDP {self.host}:{self.port} activo", flush=True)
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                self._packets_seen += 1
                try:
                    flows = self._parse_v9(data, addr[0])
                except Exception as e:
                    self._parse_errors += 1
                    if self._parse_errors <= 3:
                        print(f"[netflow] parse error: {type(e).__name__}: {e}", flush=True)
                    continue
                for f in flows:
                    self._flows_seen += 1
                    if self._is_duplicate(f):
                        continue
                    self._flows_emitted += 1
                    try:
                        on_flow(f)
                    except Exception as e:
                        print(f"[netflow] callback error: {e}", flush=True)
        finally:
            sock.close()

    def _parse_v9(self, data: bytes, exporter: str) -> List[Dict[str, Any]]:
        if len(data) < 20:
            return []
        version, count, _uptime, _secs, _seq, source_id = struct.unpack("!HHIIII", data[:20])
        if version != 9:
            return []  # ignoramos v5/IPFIX por ahora — fácil de extender

        flows: List[Dict[str, Any]] = []
        offset = 20

        while offset + 4 <= len(data):
            flowset_id, flowset_length = struct.unpack("!HH", data[offset:offset + 4])
            if flowset_length < 4 or offset + flowset_length > len(data):
                break
            content = data[offset + 4:offset + flowset_length]
            offset += flowset_length
            self._flowsets_seen += 1

            if flowset_id == 0:
                # Template flowset
                self._parse_templates(content, exporter, source_id)
            elif flowset_id == 1:
                # Options template — lo ignoramos
                continue
            elif flowset_id >= 256:
                # Data flowset asociado al template flowset_id
                key = (exporter, source_id, flowset_id)
                template = self._templates.get(key)
                if not template:
                    continue  # template aún no recibido
                flows.extend(self._parse_data_flowset(content, template, exporter))

        return flows

    def _parse_templates(self, content: bytes, exporter: str, source_id: int) -> None:
        off = 0
        while off + 4 <= len(content):
            template_id, field_count = struct.unpack("!HH", content[off:off + 4])
            off += 4
            fields: List[Tuple[int, int]] = []
            for _ in range(field_count):
                if off + 4 > len(content):
                    break
                ftype, flen = struct.unpack("!HH", content[off:off + 4])
                off += 4
                fields.append((ftype, flen))
            if fields:
                self._templates[(exporter, source_id, template_id)] = fields
                self._templates_seen += 1

    def _parse_data_flowset(
        self,
        content: bytes,
        template: List[Tuple[int, int]],
        exporter: str,
    ) -> List[Dict[str, Any]]:
        record_size = sum(flen for _, flen in template)
        if record_size == 0:
            return []
        out: List[Dict[str, Any]] = []
        off = 0
        # Cisco a veces añade padding al final del flowset; iteramos hasta
        # que no quepa otro record completo.
        while off + record_size <= len(content):
            raw_fields: Dict[str, Any] = {}
            for ftype, flen in template:
                value = self._decode_field(ftype, content[off:off + flen])
                off += flen
                raw_fields[FIELD_NAMES.get(ftype, f"FIELD_{ftype}")] = value
            normalized = self._normalize(raw_fields, exporter)
            if normalized:
                out.append(normalized)
        return out

    @staticmethod
    def _decode_field(ftype: int, raw: bytes) -> Any:
        if ftype in IPV4_FIELDS:
            return ".".join(str(b) for b in raw) if len(raw) == 4 else None
        # Resto: enteros big-endian de longitud variable.
        return int.from_bytes(raw, "big") if raw else 0

    @staticmethod
    def _normalize(d: Dict[str, Any], exporter: str) -> Optional[Dict[str, Any]]:
        src_ip = d.get("IPV4_SRC_ADDR")
        dst_ip = d.get("IPV4_DST_ADDR")
        if not src_ip or not dst_ip:
            return None
        proto_num = int(d.get("PROTOCOL", 0) or 0)
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(d.get("L4_SRC_PORT", 0) or 0),
            "dst_port": int(d.get("L4_DST_PORT", 0) or 0),
            "protocol_num": proto_num,
            "protocol": PROTOCOL_NAMES.get(proto_num, f"proto-{proto_num}"),
            "packets": int(d.get("IN_PKTS", 0) or 0),
            "bytes": int(d.get("IN_BYTES", 0) or 0),
            "exporter": exporter,
        }
