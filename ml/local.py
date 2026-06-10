"""Modelo local adaptativo: Isolation Forest sobre el tráfico propio.

Esta es la mitad "adaptativa" del híbrido (la inmunidad adquirida): aprende
la línea base de TU red desde la tabla `flows` de SQLite y se re-entrena
periódicamente con una ventana móvil, de modo que la noción de "normal"
evoluciona junto con la red.

A diferencia del modelo heredado (supervisado, patrones conocidos), este no
sabe nada de ataques: marca como anómalo lo que se desvía de la línea base
local — incluyendo ataques que CICIDS2017 nunca vio.

Diseño:
  * `retrain_from_storage()` corre en el hilo que lo invoque (el servidor lo
    programará cada RETRAIN_INTERVAL); el swap del modelo es atómico bajo lock.
  * Con menos de MIN_FLOWS flujos en la ventana el modelo se declara
    "not ready" y se abstiene (score None) — mejor sin opinión que opinión
    basada en 30 flujos.
  * Isolation Forest trabaja en espacio log (ver ml/features.py): sus cortes
    son sensibles a la escala, y bytes/duración cubren 6+ órdenes de magnitud.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional

from sklearn.ensemble import IsolationForest

from .features import featurize_flow, featurize_flows, to_log_space

# Ventana móvil de entrenamiento: 7 días de flujos.
TRAIN_WINDOW_S = 7 * 24 * 3600
# Tope de flujos por entrenamiento (los más recientes) — mantiene el fit en ms.
MAX_TRAIN_FLOWS = 50_000
# Mínimo para opinar: por debajo, la línea base no es estadísticamente seria.
MIN_FLOWS = 200
# Presupuesto de falsos positivos sobre el propio tráfico.
CONTAMINATION = 0.02


class LocalModel:
    """Isolation Forest re-entrenable. Thread-safe para fit/score concurrentes."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model: Optional[IsolationForest] = None
        self._trained_at: Optional[float] = None
        self._train_size = 0

    # ---- Entrenamiento ----

    def fit(self, flows: list[Dict[str, Any]]) -> bool:
        """Entrena con una lista de flujos. Devuelve True si quedó listo."""
        if len(flows) < MIN_FLOWS:
            with self._lock:
                # No degradamos un modelo existente: si ya había línea base
                # y la ventana se vació (red apagada), conservamos la última.
                if self._model is None:
                    self._train_size = len(flows)
            return self.ready
        x = to_log_space(featurize_flows(flows))
        model = IsolationForest(
            n_estimators=150,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(x)
        with self._lock:
            self._model = model
            self._trained_at = time.time()
            self._train_size = len(flows)
        return True

    def retrain_from_storage(self, storage: Any) -> bool:
        """Re-entrena desde la tabla `flows` (ventana móvil). Devuelve ready."""
        flows = storage.query_flows(
            since=time.time() - TRAIN_WINDOW_S,
            limit=MAX_TRAIN_FLOWS,
        )
        return self.fit(flows)

    # ---- Inferencia ----

    def score(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evalúa un flujo contra la línea base local.

        Devuelve None si el modelo aún no está listo. Si está listo:
          {"is_anomaly": bool, "score": float}
        donde score es el decision_function de sklearn (negativo = anómalo).
        """
        with self._lock:
            model = self._model
        if model is None:
            return None
        x = to_log_space(featurize_flow(flow).reshape(1, -1))
        return {
            "is_anomaly": bool(model.predict(x)[0] == -1),
            "score": float(model.decision_function(x)[0]),
        }

    # ---- Estado ----

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._model is not None

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "ready": self._model is not None,
                "trained_at": self._trained_at,
                "train_size": self._train_size,
                "min_flows": MIN_FLOWS,
            }
