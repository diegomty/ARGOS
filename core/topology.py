"""Modelo lógico de la topología de red.

Lee `topology.yaml` y expone una API tipada para consultar nodos y enlaces.
Lo usan tanto el endpoint `/api/topology` (Fase F2) como `responder.py`
para mapear una IP atacante al subif Cisco correspondiente y aplicar la
ACL en el segmento correcto en lugar de hacerlo siempre en `f0/1`.
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class NodeType(str, Enum):
    SENTINEL = "sentinel"
    ROUTER = "router"
    SWITCH = "switch"
    DEPARTMENT = "department"
    HOST = "host"
    EXTERNAL = "external"


class LinkType(str, Enum):
    TRUNK = "trunk"
    ACCESS = "access"
    EXTERNAL = "external"
    MGMT = "mgmt"


@dataclass
class Node:
    id: str
    label: str
    type: NodeType
    ip: Optional[str] = None
    subnet: Optional[str] = None         # CIDR p.ej. "10.10.20.0/24"
    vlan: Optional[int] = None
    interface: Optional[str] = None      # subif del router p.ej. "f1/0.20"
    parent: Optional[str] = None         # id del nodo contenedor (depto)
    position: Optional[List[float]] = None  # [x,y,z] hint para el renderer
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Link:
    source: str
    target: str
    type: LinkType
    bandwidth: Optional[int] = None      # Mbps
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class Topology:
    name: str
    version: str
    nodes: List[Node]
    links: List[Link]

    # ---- lookups directos ----

    def node(self, node_id: str) -> Optional[Node]:
        return next((n for n in self.nodes if n.id == node_id), None)

    def children_of(self, parent_id: str) -> List[Node]:
        return [n for n in self.nodes if n.parent == parent_id]

    def links_of(self, node_id: str) -> List[Link]:
        return [l for l in self.links if l.source == node_id or l.target == node_id]

    # ---- lookups por IP — el caso de uso más importante para el responder ----

    def find_by_ip(self, ip: str) -> Optional[Node]:
        """Devuelve el nodo más específico que contiene esa IP.

        Prioriza match exacto en `node.ip` (host concreto). Si no hay,
        busca el nodo cuyo `subnet` contenga la IP (típicamente el
        departamento o la zona externa). Devuelve None si la IP no cae
        en ningún segmento conocido.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None

        # 1) Match exacto contra hosts/router/sentinel
        for n in self.nodes:
            if n.ip and n.ip == ip:
                return n

        # 2) Containment: nodo cuya subnet incluya la IP
        candidates: List[Node] = []
        for n in self.nodes:
            if not n.subnet:
                continue
            try:
                net = ipaddress.ip_network(n.subnet, strict=False)
                if addr in net:
                    candidates.append(n)
            except ValueError:
                continue

        if not candidates:
            return None

        # Devolvemos el match más específico (prefijo más largo)
        candidates.sort(key=lambda n: ipaddress.ip_network(n.subnet, strict=False).prefixlen, reverse=True)
        return candidates[0]

    def department_for_ip(self, ip: str) -> Optional[Node]:
        """Como `find_by_ip` pero garantiza que el resultado sea un
        departamento o la zona externa — útil para decidir qué interfaz
        del router usar al aplicar una ACL."""
        node = self.find_by_ip(ip)
        if node is None:
            return None
        if node.type in (NodeType.DEPARTMENT, NodeType.EXTERNAL):
            return node
        if node.parent:
            return self.node(node.parent)
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "nodes": [n.to_dict() for n in self.nodes],
            "links": [l.to_dict() for l in self.links],
        }


# ---- carga desde YAML ----

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "topology.yaml"


def load(path: Optional[Path | str] = None) -> Topology:
    """Carga `topology.yaml` y lo convierte al modelo tipado.

    Lanza `FileNotFoundError` si el archivo no existe y `ValueError` si
    algún nodo referenciado en `links` no está declarado en `nodes`.
    """
    p = Path(path) if path else DEFAULT_PATH
    with open(p, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    nodes = [_parse_node(n) for n in raw.get("nodes", [])]
    links = [_parse_link(l) for l in raw.get("links", [])]

    # Validación: todos los endpoints de links deben existir como nodos.
    valid_ids = {n.id for n in nodes}
    for l in links:
        if l.source not in valid_ids:
            raise ValueError(f"link referencia source inexistente: {l.source!r}")
        if l.target not in valid_ids:
            raise ValueError(f"link referencia target inexistente: {l.target!r}")

    # Validación: parent debe existir.
    for n in nodes:
        if n.parent and n.parent not in valid_ids:
            raise ValueError(f"node {n.id!r} declara parent inexistente: {n.parent!r}")

    return Topology(
        name=raw.get("name", "unnamed"),
        version=str(raw.get("version", "0")),
        nodes=nodes,
        links=links,
    )


def _parse_node(raw: dict) -> Node:
    return Node(
        id=raw["id"],
        label=raw["label"],
        type=NodeType(raw["type"]),
        ip=raw.get("ip"),
        subnet=raw.get("subnet"),
        vlan=raw.get("vlan"),
        interface=raw.get("interface"),
        parent=raw.get("parent"),
        position=raw.get("position"),
        metadata=raw.get("metadata", {}) or {},
    )


def _parse_link(raw: dict) -> Link:
    return Link(
        source=raw["source"],
        target=raw["target"],
        type=LinkType(raw["type"]),
        bandwidth=raw.get("bandwidth"),
        metadata=raw.get("metadata", {}) or {},
    )
