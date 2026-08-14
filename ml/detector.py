"""Detector híbrido: combina el modelo heredado (CICIDS) y el local adaptativo.

Veredicto por flujo — la lógica inmunológica completa:

  * Modelo heredado (RandomForest supervisado): "¿este flujo se parece a un
    patrón de ataque conocido?" — memoria inmunológica heredada.
  * Modelo local (Isolation Forest sobre el tráfico propio): "¿este flujo se
    desvía de la línea base de ESTA red?" — inmunidad adquirida.

Un flujo es anómalo si CUALQUIERA de los dos lo marca (OR). El veredicto
incluye quién lo marcó y con qué score, para que el dashboard explique el
porqué en vez de dar un booleano opaco.

Degradación elegante:
  * Sin `ml/models/cicids.joblib` (no se corrió `python -m ml.train`) →
    opina solo el local.
  * Modelo local sin línea base suficiente (<200 flujos en la ventana) →
    opina solo el heredado.
  * Ambos ausentes → todo flujo se reporta como no-anómalo con
    `detectors: []`, y `stats()` lo hace visible.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from .features import featurize_flow
from .local import LocalModel

ROOT = Path(__file__).resolve().parent.parent
INHERITED_MODEL_PATH = ROOT / "ml" / "models" / "cicids.joblib"


class HybridDetector:
    """Punto único de inferencia ML para flujos NetFlow en vivo."""

    def __init__(self, model_path: Path = INHERITED_MODEL_PATH) -> None:
        self.local = LocalModel()
        self._inherited = None
        self._inherited_error: Optional[str] = None
        self._lock = threading.Lock()
        self._evaluated = 0
        self._flagged = 0
        try:
            self._inherited = joblib.load(model_path)
            # Predecir un flujo a la vez no se beneficia del paralelismo; forzar
            # n_jobs=1 evita el UserWarning de joblib en cada predicción.
            try:
                self._inherited.n_jobs = 1
            except Exception:
                pass
            print(f"[ml] modelo heredado cargado: {model_path.name}", flush=True)
        except FileNotFoundError:
            self._inherited_error = (
                f"{model_path} no existe — entrénalo con `python -m ml.train`"
            )
            print(f"[ml] WARNING: {self._inherited_error}", flush=True)
        except Exception as e:
            self._inherited_error = f"{type(e).__name__}: {e}"
            print(f"[ml] WARNING: modelo heredado no cargó — {self._inherited_error}", flush=True)

    # ---- Inferencia ----

    def evaluate(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Evalúa un flujo. Devuelve el veredicto combinado.

        {
          "is_anomaly": bool,
          "detectors": ["inherited", "local"],   # quién lo marcó
          "inherited": {"is_attack": bool, "confidence": float} | None,
          "local":     {"is_anomaly": bool, "score": float} | None,
        }
        """
        x = featurize_flow(flow).reshape(1, -1)

        inherited: Optional[Dict[str, Any]] = None
        if self._inherited is not None:
            # predict_proba[:, 1] = probabilidad de la clase "ataque".
            proba = float(self._inherited.predict_proba(x)[0, 1])
            inherited = {"is_attack": proba >= 0.5, "confidence": proba}

        local = self.local.score(flow)

        detectors = []
        if inherited and inherited["is_attack"]:
            detectors.append("inherited")
        if local and local["is_anomaly"]:
            detectors.append("local")

        with self._lock:
            self._evaluated += 1
            if detectors:
                self._flagged += 1

        return {
            "is_anomaly": bool(detectors),
            "detectors": detectors,
            "inherited": inherited,
            "local": local,
        }

    # ---- Entrenamiento local ----

    def retrain_local(self, storage: Any) -> bool:
        """Re-entrena la línea base local desde SQLite. Devuelve ready."""
        t0 = time.perf_counter()
        ready = self.local.retrain_from_storage(storage)
        st = self.local.stats()
        print(
            f"[ml] retrain local: ready={ready} "
            f"({st['train_size']} flujos, {time.perf_counter() - t0:.2f}s)",
            flush=True,
        )
        return ready

    # ---- Estado ----

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            evaluated, flagged = self._evaluated, self._flagged
        return {
            "inherited_loaded": self._inherited is not None,
            "inherited_error": self._inherited_error,
            "local": self.local.stats(),
            "evaluated": evaluated,
            "flagged": flagged,
        }
