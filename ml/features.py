"""Vector de features compartido por toda la capa ML.

El mismo vector se construye desde tres orígenes distintos y DEBE ser
idéntico en los tres (mismo orden, mismas fórmulas, mismos pisos):

  * ml/prepare_cicids.py — desde los CSVs de CICIDS2017 (entrenamiento heredado)
  * ml/local.py          — desde rows de la tabla `flows` (entrenamiento local)
  * ml/detector.py       — desde el dict que emite FlowListener (inferencia)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

import numpy as np

FEATURE_NAMES = [
    "dst_port",
    "duration_ms",
    "packets",
    "bytes",
    "bytes_per_packet",
    "packets_per_s",
    "bytes_per_s",
]

# Columnas que viven en escala logarítmica para modelos sensibles a la
# distancia (Isolation Forest). Los modelos de árboles supervisados no la
# necesitan, pero no les estorba usar el mismo espacio.
LOG_COLS = [1, 2, 3, 4, 5, 6]


def featurize_flow(flow: Dict[str, Any]) -> np.ndarray:
    """Dict de flujo (FlowListener o row de la tabla `flows`) → vector (7,).

    Mismas fórmulas que ml/prepare_cicids.py: piso de 1 paquete en los
    promedios y de 1 ms en las tasas para evitar divisiones por cero.
    """
    packets = float(flow.get("packets", 0) or 0)
    bytes_total = float(flow.get("bytes", 0) or 0)
    duration_ms = max(float(flow.get("duration_ms", 0) or 0), 0.0)
    duration_s = max(duration_ms, 1.0) / 1000.0
    return np.array([
        float(flow.get("dst_port", 0) or 0),
        duration_ms,
        packets,
        bytes_total,
        bytes_total / max(packets, 1.0),
        packets / duration_s,
        bytes_total / duration_s,
    ], dtype=np.float64)


def featurize_flows(flows: Iterable[Dict[str, Any]]) -> np.ndarray:
    """Lista de flujos → matriz (n, 7)."""
    rows: List[np.ndarray] = [featurize_flow(f) for f in flows]
    return np.vstack(rows) if rows else np.empty((0, len(FEATURE_NAMES)))


def to_log_space(x: np.ndarray) -> np.ndarray:
    """log1p sobre las columnas de magnitud (para Isolation Forest)."""
    out = x.astype(np.float64).copy()
    out[:, LOG_COLS] = np.log1p(np.maximum(out[:, LOG_COLS], 0))
    return out
