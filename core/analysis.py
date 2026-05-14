"""Motor estadístico: entropía de Shannon, SHA-3 y correlación L3."""

import hashlib
import math
import re
from collections import Counter
from typing import Optional, Tuple

from . import config


def calcular_entropia(texto: str) -> float:
    """H(X) = -Σ P(xi) log2 P(xi) sobre los caracteres del mensaje."""
    if not texto:
        return 0.0
    longitud = len(texto)
    return -sum(
        (frec / longitud) * math.log2(frec / longitud)
        for frec in Counter(texto).values()
    )


def hash_sha3(texto: str) -> str:
    """Hash SHA-3-256 hex del mensaje — cadena de custodia post-cuántica."""
    return hashlib.sha3_256(texto.encode("utf-8")).hexdigest()


def es_confiable(mensaje: str) -> bool:
    return any(palabra in mensaje for palabra in config.PALABRAS_CONFIANZA)


_REGEX_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def extraer_ip_atacante(log_texto: str) -> Optional[str]:
    """Plan A: primera IP del log que no sea el router admin ni loopback."""
    for ip in _REGEX_IP.findall(log_texto):
        if ip != config.IP_ROUTER_ADMIN and ip != "127.0.0.1":
            return ip
    return None


def identificar_atacante(mensaje: str) -> Tuple[Optional[str], str]:
    """Devuelve (ip, plan) — plan ∈ {'A', 'B', 'NONE'}.

    Plan A: la IP viene en el log.
    Plan B: el log dice UNKNOWN → usamos la subred de ataque conocida.
    NONE  : no se pudo correlacionar.
    """
    ip = extraer_ip_atacante(mensaje)
    if ip:
        return ip, "A"
    if "UNKNOWN" in mensaje:
        return config.IP_ATACANTE_FALLBACK, "B"
    return None, "NONE"
