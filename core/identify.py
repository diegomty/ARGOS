"""Identificación de dispositivos (Fase O): pone nombre y fabricante a las IPs.

En una red real un nodo "192.168.0.106" no dice nada. Este módulo lo enriquece
con lo que se puede averiguar de forma LOCAL y pasiva:

  * fabricante  — de la MAC (prefijo OUI) leída de la tabla ARP del sistema,
  * hostname    — por DNS inverso (PTR), si el router/host lo publica.

Las fuentes más ricas (nombre que el equipo se pone al conectarse: DHCP, mDNS)
las captura el sensor y se guardan en la tabla `identities`; aquí las leemos y
las combinamos, dando prioridad al nombre observado sobre el DNS inverso.

Todo degrada con gracia: si scapy no está, no hay ARP, o el DNS no responde,
simplemente devolvemos lo que se tenga (o nada) sin romper el descubrimiento.
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from core.discovery import _is_internal

# Cachés en memoria con TTL: sin esto, cada /api/discovery repetiría el DNS
# inverso (incluidos los negativos, que no se persisten) y el arp — volviéndose
# lento con varias IPs. Con caché, las llamadas repetidas son instantáneas.
_DNS_TTL = 300.0      # 5 min: un PTR no cambia seguido
_ARP_TTL = 20.0       # 20 s: la tabla ARP sí cambia (equipos que entran/salen)
_dns_cache: Dict[str, tuple] = {}          # ip -> (nombre|None, expira_en)
_arp_cache: Dict[str, Any] = {"t": 0.0, "table": {}}

# El DNS inverso se resuelve en SEGUNDO PLANO: en Windows puede tardar varios
# segundos por IP (el timeout de socket no lo acota), así que jamás lo hacemos
# en el camino de /api/discovery. El resultado se persiste y aparece a la
# próxima carga — igual que los nombres de DHCP/mDNS.
_resolver = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-rev")
_pending: set = set()                       # IPs con lookup en curso

# IP + MAC en la salida de `arp -a` (Windows usa '-', Unix ':' como separador).
_ARP_LINE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})"
)

# Respaldo mínimo de fabricantes por OUI (primeros 3 octetos), por si scapy no
# trae su base manuf. La base de scapy es mucho más completa y se usa primero.
_OUI_FALLBACK: Dict[str, str] = {
    "3C:5A:B4": "Google", "F4:F5:E8": "Google", "D8:3A:DD": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "00:1A:11": "Google", "AC:DE:48": "Apple",
    "F0:18:98": "Apple", "A4:83:E7": "Apple", "3C:06:30": "Apple",
    "00:1C:B3": "Apple", "5C:96:9D": "Apple", "8C:85:90": "Apple",
    "FC:FB:FB": "Cisco", "00:1B:63": "Apple", "B8:27:EB": "Raspberry Pi",
    "00:16:6C": "Samsung", "5C:0A:5B": "Samsung", "C8:BA:94": "Samsung",
    "AC:5F:3E": "Samsung", "50:32:37": "Samsung", "1C:66:6D": "Samsung",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:1D:D8": "Microsoft",
    "48:2C:6A": "Amazon", "FC:A1:83": "Amazon", "00:FC:8B": "Amazon",
}


def _normalize_mac(mac: str) -> str:
    """MAC a formato canónico en mayúsculas con ':' (AA:BB:CC:DD:EE:FF)."""
    return mac.replace("-", ":").upper()


def _is_mac_like(s: Optional[str]) -> bool:
    """True si el texto es en realidad una MAC (scapy devuelve eso si no la
    reconoce): así no confundimos "no encontrado" con un nombre de fabricante."""
    return bool(s) and bool(re.fullmatch(r"[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){2,5}", s))


def arp_table() -> Dict[str, str]:
    """Lee la tabla ARP del sistema operativo: {ip: mac}. Vacío si falla.

    Es la caché local del SO — no genera tráfico. Solo contiene equipos con los
    que esta máquina ha hablado recientemente (por eso conviene tener el sensor
    corriendo un rato: mantiene la caché fresca).
    """
    now = time.time()
    if now - _arp_cache["t"] < _ARP_TTL:
        return _arp_cache["table"]
    table = _arp_windows() if sys.platform.startswith("win") else _arp_unix()
    if table:                       # solo refresca la caché si hubo lectura útil
        _arp_cache["t"] = now
        _arp_cache["table"] = table
        return table
    return _arp_cache["table"]


def _arp_windows() -> Dict[str, str]:
    """Tabla ARP en Windows: `arp -a` (IP y MAC contiguas, separador '-')."""
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=5).stdout
    except Exception:
        return {}
    return {ip: _normalize_mac(mac) for ip, mac in _ARP_LINE.findall(out)}


def _arp_unix() -> Dict[str, str]:
    """Tabla ARP en Linux/Kali: `ip neigh` (con respaldo a `arp -n`)."""
    table: Dict[str, str] = {}
    # `ip neigh show` -> "192.168.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
    try:
        out = subprocess.run(["ip", "neigh", "show"], capture_output=True,
                             text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if "lladdr" in parts:
                ip, mac = parts[0], parts[parts.index("lladdr") + 1]
                if _is_mac_like(mac):
                    table[ip] = _normalize_mac(mac)
    except Exception:
        pass
    if table:
        return table
    # Respaldo: `arp -n` -> "192.168.0.1  ether  aa:bb:cc:dd:ee:ff  C  eth0"
    try:
        out = subprocess.run(["arp", "-n"], capture_output=True, text=True,
                             timeout=5).stdout
        for line in out.splitlines():
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?"
                          r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                table[m.group(1)] = _normalize_mac(m.group(2))
    except Exception:
        pass
    return table


def mac_vendor(mac: Optional[str]) -> Optional[str]:
    """Fabricante a partir de la MAC (prefijo OUI). Usa la base de scapy y, si
    no está disponible, un respaldo pequeño de fabricantes comunes."""
    if not mac:
        return None
    mac = _normalize_mac(mac)
    # 1) Base manuf de scapy (amplia).
    try:
        from scapy.all import conf
        db = conf.manufdb
        for meth in ("lookup", "_get_manuf"):
            fn = getattr(db, meth, None)
            if fn is None:
                continue
            try:
                res = fn(mac)
            except Exception:
                continue
            if isinstance(res, tuple):
                nombre = res[1] or res[0]   # (corto, largo) -> preferimos largo
            else:
                nombre = res
            nombre = str(nombre) if nombre else None
            # scapy devuelve la propia MAC si no reconoce el OUI: eso no es un
            # fabricante, así que lo descartamos y probamos el respaldo.
            if nombre and not _is_mac_like(nombre) and nombre.upper() != mac:
                return nombre
    except Exception:
        pass
    # 2) Respaldo por OUI (primeros 3 octetos).
    return _OUI_FALLBACK.get(mac[:8])


def reverse_dns(ip: str, timeout: float = 0.6) -> Optional[str]:
    """Nombre por DNS inverso (PTR). None si no hay registro o tarda demasiado.

    Cachea el resultado (incluido el negativo) por _DNS_TTL para no reconsultar
    en cada llamada — un PTR fallido no debe costar en cada /api/discovery."""
    hit = _dns_cache.get(ip)
    now = time.time()
    if hit is not None and hit[1] > now:
        return hit[0]
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        name = socket.gethostbyaddr(ip)[0]
        nombre = name if name and name != ip else None
    except Exception:
        nombre = None
    finally:
        socket.setdefaulttimeout(old)
    _dns_cache[ip] = (nombre, now + _DNS_TTL)
    return nombre


def _resolve_async(ip: str, storage: Any) -> None:
    """Worker de fondo: DNS inverso + persistir el nombre si aparece."""
    try:
        name = reverse_dns(ip)
        if name and storage is not None:
            storage.upsert_identity(ip, hostname=name, source="dns")
    except Exception:
        pass
    finally:
        _pending.discard(ip)


def _resolver_dns_bg(ip: str, storage: Any) -> None:
    """Encola un DNS inverso en segundo plano (sin duplicar ni reintentar en
    balde: respeta la caché con TTL, incluidos los negativos recientes)."""
    if ip in _pending:
        return
    cached = _dns_cache.get(ip)
    if cached is not None and cached[1] > time.time():
        return  # ya resuelto o negativo reciente: no reconsultar
    _pending.add(ip)
    _resolver.submit(_resolve_async, ip, storage)


def enrich_graph(graph: Dict[str, Any], storage: Any) -> Dict[str, Any]:
    """Añade a cada nodo INTERNO su hostname, fabricante y MAC.

    Combina tres fuentes por prioridad de nombre: lo ya guardado por el sensor
    (DHCP/mDNS, los mejores nombres) > DNS inverso; y para el fabricante usa la
    MAC guardada o la de la tabla ARP. Lo nuevo que se descubre se persiste en
    `identities` para que el nombre sobreviva aunque el equipo se desconecte.
    """
    known = storage.query_identities() if storage is not None else {}
    arp = arp_table()

    for node in graph.get("nodes", []):
        ip = node.get("ip", "")
        if not _is_internal(ip):
            continue
        prev = known.get(ip, {})

        mac = prev.get("mac") or arp.get(ip)
        vendor = prev.get("vendor") or mac_vendor(mac)
        # Hostname: usamos el ya conocido (DHCP/mDNS/DNS previo). Si falta, el
        # DNS inverso se resuelve en segundo plano — esta respuesta no espera.
        hostname = prev.get("hostname")
        if not hostname:
            _resolver_dns_bg(ip, storage)

        # Persistir lo rápido (mac/vendor); el hostname del DNS lo guarda el bg.
        if storage is not None and (mac or vendor):
            storage.upsert_identity(ip, mac=mac, vendor=vendor,
                                    source="arp" if (mac and not prev.get("mac")) else None)

        node["mac"] = mac
        node["vendor"] = vendor
        node["hostname"] = hostname
        # Tipo de dispositivo observado por SSDP/UPnP (TV, impresora, router…).
        device_type = prev.get("device_type")
        if device_type:
            node["device_type"] = device_type
        # Nombre a mostrar en el mapa: hostname > fabricante > tipo > (la IP).
        nombre = hostname or vendor or device_type
        if nombre:
            node["device_name"] = nombre
    return graph
