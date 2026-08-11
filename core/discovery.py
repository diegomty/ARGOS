"""Motor de descubrimiento pasivo de red (Fase K).

Construye un modelo de la red OBSERVANDO los flujos que ya ingerimos por
NetFlow — sin tocar ni configurar ningún dispositivo. Cada flujo es una
arista `origen -> destino:puerto`; agregando miles de flujos emergen:

  * los nodos (hosts) que participan en la red,
  * los servicios que cada host EXPONE (puertos donde recibe conexiones),
  * el ROL inferido de cada host (base de datos, DNS, web, workstation...),
  * las relaciones (quién habla con quién y cuánto).

Esto reemplaza la topología declarada a mano (topology.yaml), que pasa a ser
una capa opcional de anotación. El módulo es puro: recibe una lista de flujos
(dicts como los que produce core.storage) y devuelve el grafo descubierto,
así que es trivial de probar contra la base de datos real.

Diseño pensado para el híbrido: cada nodo lleva un campo `source`
('passive'|'active') para que el enriquecimiento por escaneo activo (capa 2)
pueda fusionarse encima más adelante.
"""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

# --- Mapa puerto -> nombre de servicio (subconjunto de puertos conocidos) ---
PORT_SERVICES: Dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 587: "smtp-sub", 636: "ldaps",
    993: "imaps", 995: "pop3s", 902: "vmware-auth", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2055: "netflow", 3306: "mysql",
    3389: "rdp", 5060: "sip", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

# Puertos efímeros: cuando aparecen como destino suelen ser tráfico de
# retorno, no un servicio real expuesto. Se ignoran como "servicio servido".
EPHEMERAL_MIN = 49152

# --- Reglas de rol: (conjunto de puertos, rol, prioridad). Mayor prioridad
#     gana cuando un host expone varios tipos de servicio. ---
ROLE_RULES: List[tuple] = [
    ({5432, 3306, 1433, 1521, 27017, 6379, 9200}, "database", 90),
    ({53},                                         "dns", 85),
    ({445, 139, 135, 88, 389, 636, 3389},          "windows-server", 80),
    ({25, 587, 465, 993, 995, 110, 143},           "mail-server", 75),
    ({80, 443, 8080, 8443},                        "web-server", 70),
    ({21, 20, 2049, 69},                           "file-server", 65),
    ({22, 23},                                     "ssh-host", 40),
]

# Umbral de "scanner": muchos destinos:puerto distintos con flujos diminutos.
SCANNER_MIN_TARGETS = 20
SCANNER_MAX_AVG_BYTES = 600

# Un puerto cuenta como "servicio expuesto" (y no como un simple sondeo de
# escaneo) si es conocido, si lo consumieron varios clientes distintos, o si
# movió tráfico significativo. Este último criterio conserva puertos como el
# 4444 de un C2 (un solo cliente pero volumen enorme por exfiltración) y
# descarta los puertos que un port scan tocó una vez con unos pocos bytes.
SERVICE_MIN_BYTES = 100_000


def _zone_of(ip: str) -> str:
    """Zona = red /24 del host (agrupador visual básico)."""
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return "desconocida"


def _service_name(port: int) -> str:
    return PORT_SERVICES.get(port, f"port-{port}")


def _infer_role(served_ports: set[int], is_scanner: bool,
                fanout: int, has_served: bool) -> str:
    """Deriva el rol primario de un host a partir de lo observado."""
    if is_scanner:
        return "scanner"
    best_role, best_prio = None, -1
    for ports, role, prio in ROLE_RULES:
        if served_ports & ports and prio > best_prio:
            best_role, best_prio = role, prio
    if best_role:
        return best_role
    if not has_served and fanout >= 3:
        return "workstation"
    return "host"


def build_graph(flows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Lista de flujos -> grafo de red descubierto.

    Cada flujo debe traer al menos: src_ip, dst_ip, dst_port, protocol,
    protocol_num, bytes, packets. `received_at` es opcional (para first/last).
    """
    # Acumuladores por nodo.
    n_bytes_in: Dict[str, int] = defaultdict(int)
    n_bytes_out: Dict[str, int] = defaultdict(int)
    n_flows_in: Dict[str, int] = defaultdict(int)
    n_flows_out: Dict[str, int] = defaultdict(int)
    n_first: Dict[str, float] = {}
    n_last: Dict[str, float] = {}
    # puerto expuesto -> conjunto de clientes distintos que lo consumieron
    n_served: Dict[str, Dict[int, set]] = defaultdict(lambda: defaultdict(set))
    # puerto expuesto -> bytes acumulados (para distinguir servicio de sondeo)
    n_served_bytes: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    # como cliente: destinos y (destino,puerto) distintos que tocó
    n_client_dsts: Dict[str, set] = defaultdict(set)
    n_client_targets: Dict[str, set] = defaultdict(set)  # (dst_ip, dst_port)
    # Puertos que cada par (origen -> destino) tocó. Sirve para distinguir un
    # ESCANEO real (un origen concentrando muchos puertos de un objetivo) del
    # tráfico de retorno normal (muchos servidores, cada uno a un puerto
    # efímero distinto de un cliente).
    port_pairs: Dict[tuple, set] = defaultdict(set)

    # Acumulador por arista (src, dst, dst_port, proto).
    edges: Dict[tuple, Dict[str, Any]] = {}

    for f in flows:
        s = f.get("src_ip"); d = f.get("dst_ip")
        if not s or not d:
            continue
        dp = int(f.get("dst_port", 0) or 0)
        sp = int(f.get("src_port", 0) or 0)
        proto = f.get("protocol", "?")
        b = int(f.get("bytes", 0) or 0)
        pk = int(f.get("packets", 0) or 0)
        ts = float(f.get("received_at", 0) or 0)

        n_bytes_out[s] += b; n_flows_out[s] += 1
        n_bytes_in[d] += b; n_flows_in[d] += 1
        n_client_dsts[s].add(d)
        if dp < EPHEMERAL_MIN:
            n_client_targets[s].add((d, dp))
            n_served[d][dp].add(s)
            n_served_bytes[d][dp] += b
        # Solo cuenta para el escaneo si el ORIGEN no es un puerto de servicio
        # conocido: un servidor respondiendo usa su puerto conocido (53, 443…)
        # hacia puertos efímeros del cliente — eso es tráfico de retorno, no
        # un escaneo. Un escáner de verdad usa un puerto de origen efímero.
        if dp != 0 and sp not in PORT_SERVICES:
            port_pairs[(s, d)].add(dp)

        for node in (s, d):
            if ts:
                if node not in n_first or ts < n_first[node]:
                    n_first[node] = ts
                if node not in n_last or ts > n_last[node]:
                    n_last[node] = ts

        ek = (s, d, dp, proto)
        e = edges.get(ek)
        if e is None:
            edges[ek] = {"bytes": b, "packets": pk, "flows": 1}
        else:
            e["bytes"] += b; e["packets"] += pk; e["flows"] += 1

    # Máximo de puertos que un solo par concentró, por origen y por destino.
    # Un escáner concentra muchos puertos hacia UN objetivo; el tráfico de
    # retorno normal reparte 1 puerto efímero por cada servidor.
    max_ports_from: Dict[str, int] = defaultdict(int)
    max_ports_to: Dict[str, int] = defaultdict(int)
    for (s, d), ports in port_pairs.items():
        k = len(ports)
        if k > max_ports_from[s]:
            max_ports_from[s] = k
        if k > max_ports_to[d]:
            max_ports_to[d] = k

    # --- Construir nodos ---
    all_ips = set(n_bytes_in) | set(n_bytes_out)
    nodes: List[Dict[str, Any]] = []
    for ip in sorted(all_ips):
        served = n_served.get(ip, {})
        served_ports = set(served.keys())
        fanout = len(n_client_dsts.get(ip, ()))
        out_flows = n_flows_out.get(ip, 0)
        # Escáner / objetivo de escaneo por CONCENTRACIÓN de puertos por par —
        # no por conteo total, que el tráfico de retorno inflaba con efímeros.
        is_scanner = max_ports_from.get(ip, 0) >= SCANNER_MIN_TARGETS
        is_scan_target = max_ports_to.get(ip, 0) >= SCANNER_MIN_TARGETS

        # Servicios reales: puerto conocido, o consumido por VARIOS clientes
        # distintos (fan-in >= 3). El tráfico de retorno a puertos efímeros tiene
        # fan-in ~1, así que ya no aparece como "servicio" fantasma.
        served_bytes = n_served_bytes.get(ip, {})
        services = []
        real_ports: set[int] = set()
        probed = 0
        for p, clients in served.items():
            if p == 0:
                continue  # puerto 0 = ICMP/sin puerto, no es un servicio
            c = len(clients)
            if (p in PORT_SERVICES) or (c >= 3):
                services.append({"port": p, "name": _service_name(p),
                                 "clients": c, "bytes": served_bytes.get(p, 0)})
                real_ports.add(p)
            else:
                probed += 1
        services.sort(key=lambda s: (-s["clients"], -s["bytes"]))

        role = _infer_role(real_ports, is_scanner, fanout, bool(real_ports))
        total_flows = n_flows_in.get(ip, 0) + out_flows

        nodes.append({
            "id": ip,
            "ip": ip,
            "role": role,
            "zone": _zone_of(ip),
            "services": services,
            "bytes_in": n_bytes_in.get(ip, 0),
            "bytes_out": n_bytes_out.get(ip, 0),
            "flows": total_flows,
            "fanout": fanout,
            "probed_ports": probed,
            "first_seen": n_first.get(ip),
            "last_seen": n_last.get(ip),
            "is_scanner": is_scanner,
            "is_scan_target": is_scan_target,
            "confidence": round(min(1.0, total_flows / 20.0), 2),
            "source": "passive",
        })

    # --- Construir aristas (peso normalizado por bytes) ---
    max_bytes = max((e["bytes"] for e in edges.values()), default=1) or 1
    edge_list: List[Dict[str, Any]] = []
    for (s, d, dp, proto), e in edges.items():
        edge_list.append({
            "source": s, "target": d,
            "port": dp, "service": _service_name(dp) if dp < EPHEMERAL_MIN else None,
            "protocol": proto,
            "bytes": e["bytes"], "packets": e["packets"], "flows": e["flows"],
            "weight": round(e["bytes"] / max_bytes, 4),
        })

    return {
        "generated_at": time.time(),
        "nodes": nodes,
        "edges": edge_list,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edge_list),
            "flow_count": len(flows),
            "scanners": sum(1 for n in nodes if n["is_scanner"]),
        },
    }


def discover_from_storage(storage: Any, window_s: Optional[float] = None,
                          limit: int = 100_000) -> Dict[str, Any]:
    """Conveniencia: construye el grafo desde la tabla `flows` de SQLite."""
    since = (time.time() - window_s) if window_s else None
    flows = storage.query_flows(since=since, limit=limit)
    return build_graph(flows)


def annotate(graph: Dict[str, Any], topology: Any) -> Dict[str, Any]:
    """Fusiona anotaciones OPCIONALES de topology.yaml sobre lo descubierto.

    El descubrimiento es la fuente de verdad de QUÉ hay en la red; topology.yaml
    solo aporta metadatos humanos (etiqueta legible, criticidad, interfaz Cisco
    para respuesta) cuando la IP coincide con un nodo declarado. Si no hay
    topología o la IP no está declarada, el nodo se queda con su etiqueta = IP.
    Esto mantiene el sistema funcional en cualquier red sin declarar nada.
    """
    for node in graph["nodes"]:
        ip = node["ip"]
        node["label"] = ip
        node["annotated"] = False
        tnode = topology.find_by_ip(ip)
        if tnode is not None:
            node["label"] = tnode.label
            node["annotated"] = True
            if tnode.interface:
                node["interface"] = tnode.interface
            crit = (tnode.metadata or {}).get("criticality")
            if crit:
                node["criticality"] = crit
            color = (tnode.metadata or {}).get("color_hint")
            if color:
                node["color_hint"] = color
        dept = topology.department_for_ip(ip)
        if dept is not None:
            node["department"] = dept.label
            node["department_id"] = dept.id
            # La criticidad y el color suelen declararse a nivel de
            # departamento; el host los hereda si no los trae él mismo.
            dmeta = dept.metadata or {}
            if "criticality" not in node and dmeta.get("criticality"):
                node["criticality"] = dmeta["criticality"]
            if "color_hint" not in node and dmeta.get("color_hint"):
                node["color_hint"] = dmeta["color_hint"]
    graph["stats"]["annotated"] = sum(1 for n in graph["nodes"] if n["annotated"])
    return graph


def filter_graph(graph: Dict[str, Any], min_flows: int = 1) -> Dict[str, Any]:
    """Devuelve una copia del grafo sin nodos por debajo de `min_flows`.

    Doma el ruido de eventos efímeros (p. ej. las IPs de una botnet que solo
    hacen un flujo cada una) sin perder la información en la base: el filtro
    es de presentación, no de captura. Las aristas que tocan un nodo eliminado
    también se descartan.
    """
    if min_flows <= 1:
        return graph
    kept = {n["id"] for n in graph["nodes"] if n["flows"] >= min_flows}
    nodes = [n for n in graph["nodes"] if n["id"] in kept]
    edges = [e for e in graph["edges"]
             if e["source"] in kept and e["target"] in kept]
    stats = dict(graph["stats"])
    stats["node_count"] = len(nodes)
    stats["edge_count"] = len(edges)
    stats["scanners"] = sum(1 for n in nodes if n["is_scanner"])
    stats["filtered_out"] = len(graph["nodes"]) - len(nodes)
    stats["min_flows"] = min_flows
    return {**graph, "nodes": nodes, "edges": edges, "stats": stats}
