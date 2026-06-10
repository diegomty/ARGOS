"""Entrena el modelo "heredado" de Q-Sentinel con CICIDS2017 etiquetado.

Filosofía (metáfora inmunológica del proyecto): este modelo es la memoria
inmunológica heredada — anticuerpos supervisados contra patrones de ataque
conocidos (DoS, scans, fuerza bruta...). El modelo local adaptativo
(Isolation Forest sobre el tráfico propio, siguiente paso) es la respuesta
inmune adquirida, que cubre lo que este modelo no vio en su entrenamiento.

Por qué supervisado y no Isolation Forest:
  Un flujo individual de PortScan o DoS Hulk NO es un outlier — se parece a
  un flujo benigno chico (2 paquetes, microsegundos). Medido: Isolation
  Forest sobre estas mismas features detecta <1% de los ataques; un
  RandomForest con las etiquetas detecta ~97%. La frontera benign/ataque
  existe en el espacio de features, pero solo las etiquetas la revelan.

Vector de entrada (idéntico al que produce el detector en vivo):
  [0] dst_port  [1] duration_ms  [2] packets  [3] bytes
  [4] bytes_per_packet  [5] packets_per_s  [6] bytes_per_s

Limitación honesta: el split de validación es aleatorio, así que el recall
mide reconocimiento de patrones de ataque *presentes en CICIDS*, no
generalización a ataques novedosos — para eso está el modelo local.

Uso:
    python -m ml.train
"""

from __future__ import annotations

import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parent.parent
BENIGN_NPZ = ROOT / "datasets" / "cicids_benign.npz"
ATTACKS_NPZ = ROOT / "datasets" / "cicids_attacks.npz"
MODEL_PATH = ROOT / "ml" / "models" / "cicids.joblib"

TEST_FRACTION = 0.25


def main() -> None:
    benign = np.load(BENIGN_NPZ, allow_pickle=True)["x"]
    attacks_npz = np.load(ATTACKS_NPZ, allow_pickle=True)
    attacks, attack_labels = attacks_npz["x"], attacks_npz["labels"]

    x = np.vstack([benign, attacks])
    y = np.concatenate([np.zeros(len(benign)), np.ones(len(attacks))])
    # Conservamos el tipo de ataque por fila para el reporte por clase.
    detail = np.concatenate([np.array(["BENIGN"] * len(benign)), attack_labels])

    xtr, xte, ytr, yte, _, det_te = train_test_split(
        x, y, detail,
        test_size=TEST_FRACTION,
        random_state=42,
        stratify=detail,  # mantiene la proporción de cada tipo de ataque
    )

    print(f"Entrenando con {len(xtr):,} flujos ({int(ytr.sum()):,} de ataque)...")
    t0 = time.perf_counter()
    model = RandomForestClassifier(
        n_estimators=150,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",  # benign supera 4:1 a los ataques
    )
    model.fit(xtr, ytr)
    print(f"  listo en {time.perf_counter() - t0:.1f}s")

    # --- Validación sobre el 25% nunca visto ---
    pred = model.predict(xte) == 1

    benign_mask = yte == 0
    fp = pred[benign_mask].mean()
    recall = pred[~benign_mask].mean()
    print(f"\nFalsos positivos (benign marcado como ataque): {fp:.2%}")
    print(f"Deteccion global de ataques: {recall:.2%}\n")

    print("Deteccion por tipo de ataque:")
    for label in sorted(set(det_te.tolist()) - {"BENIGN"}):
        m = det_te == label
        rate = pred[m].mean()
        bar = "#" * int(rate * 30)
        print(f"  {label:30s} {rate:7.2%}  ({m.sum():>6,} flujos)  {bar}")

    print("\nImportancia de features:")
    names = ["dst_port", "duration_ms", "packets", "bytes",
             "bytes_per_packet", "packets_per_s", "bytes_per_s"]
    for name, imp in sorted(zip(names, model.feature_importances_),
                            key=lambda t: -t[1]):
        print(f"  {name:18s} {imp:.3f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH, compress=3)
    size_mb = MODEL_PATH.stat().st_size / 1e6
    print(f"\n[OK] modelo guardado en {MODEL_PATH.relative_to(ROOT)} ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
