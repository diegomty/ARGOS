"""Modelo de evento que el listener emite por callback.

El mismo objeto se imprime en consola en modo CLI y se serializa a JSON
para enviarlo por WebSocket en la Fase E.
"""

from dataclasses import asdict, dataclass, field
from typing import List, Optional


@dataclass
class SentinelEvent:
    timestamp: str          # "YYYY-MM-DD HH:MM:SS.mmm"
    raw_message: str        # mensaje syslog tal como llegó
    source_ip: str          # IP UDP que envió el datagrama (suele ser el router)
    entropy: float          # H(X) en bits
    sha3: str               # hash SHA-3-256 del mensaje completo
    is_trusted: bool        # matchea la whitelist heurística
    is_anomaly: bool        # H supera el umbral y no es trusted
    attacker_ip: Optional[str] = None
    plan: str = "NONE"      # "A", "B" o "NONE" — cómo se correlacionó la IP
    blocked: bool = False
    response_log: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
