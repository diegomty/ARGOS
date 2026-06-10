"""Prepara CICIDS2017 (MachineLearningCVE) para entrenar el modelo heredado.

Extrae de los 8 CSVs únicamente las 5 features compartidas con la tabla
`flows` de Q-Sentinel y las guarda en dos .npz compactos:

  * datasets/cicids_benign.npz  — tráfico BENIGN (entrenamiento)
  * datasets/cicids_attacks.npz — tráfico de ataque + etiqueta (validación)

Vector de features (mismo orden que usará el detector en vivo):
  [0] dst_port           ←  Destination Port
  [1] duration_ms        ←  Flow Duration (µs en CICIDS → lo convertimos)
  [2] packets            ←  Total Fwd Packets + Total Backward Packets
  [3] bytes              ←  Total Length of Fwd Packets + ... Bwd Packets
  [4] bytes_per_packet   ←  bytes / packets (calculado, no la columna del CSV,
                            para que sea idéntico a lo que computamos en vivo)
  [5] packets_per_s      ←  packets / max(duration, 1ms) — firma de DoS/flood
  [6] bytes_per_s        ←  bytes / max(duration, 1ms)

Las features de tasa se calculan desde los totales (no usamos las columnas
'Flow Packets/s' del CSV, que traen NaN/Inf) para que la fórmula sea
exactamente la misma que aplicaremos a los flujos NetFlow en vivo.

Notas del dataset:
  * Los nombres de columna traen espacios iniciales inconsistentes → strip.
  * Hay filas con NaN/Inf (en 'Flow Bytes/s' etc.) — como solo usamos
    columnas de conteo, basta con descartar NaN en las nuestras.
  * BENIGN ≈ 2.27M filas; muestreamos para mantener los .npz pequeños.

Uso:
    python -m ml.prepare_cicids
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
CSV_DIR = ROOT / "datasets" / "MachineLearningCVE"
OUT_BENIGN = ROOT / "datasets" / "cicids_benign.npz"
OUT_ATTACKS = ROOT / "datasets" / "cicids_attacks.npz"

# Columnas del CSV que necesitamos (nombres ya con strip aplicado).
COLS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Label",
]

FEATURE_NAMES = [
    "dst_port", "duration_ms", "packets", "bytes", "bytes_per_packet",
    "packets_per_s", "bytes_per_s",
]

# Tamaños de muestra: Isolation Forest no necesita millones de filas y los
# .npz resultantes deben poder cargarse en segundos al entrenar.
BENIGN_SAMPLE = 300_000
ATTACK_SAMPLE_PER_LABEL = 10_000

RNG = np.random.default_rng(42)  # reproducible


def _read_csv(path: Path) -> pd.DataFrame:
    """Lee un CSV del dataset quedándose solo con las columnas necesarias."""
    # Los encabezados traen espacios iniciales ('// Destination Port') que
    # varían entre archivos: leemos el header real y mapeamos por strip.
    header = pd.read_csv(path, nrows=0)
    by_stripped = {c.strip(): c for c in header.columns}
    usecols = [by_stripped[c] for c in COLS]
    df = pd.read_csv(path, usecols=usecols)
    df.columns = [c.strip() for c in df.columns]
    return df


def _to_features(df: pd.DataFrame) -> np.ndarray:
    """DataFrame crudo → matriz (n, 7) float32 con el vector compartido."""
    packets = df["Total Fwd Packets"].to_numpy(dtype=np.float64) + \
        df["Total Backward Packets"].to_numpy(dtype=np.float64)
    bytes_total = df["Total Length of Fwd Packets"].to_numpy(dtype=np.float64) + \
        df["Total Length of Bwd Packets"].to_numpy(dtype=np.float64)
    duration_ms = df["Flow Duration"].to_numpy(dtype=np.float64) / 1000.0
    # Piso de 1 ms en las tasas: evita división por cero y acota la explosión
    # de flujos de microsegundos (la misma fórmula se usará en vivo).
    duration_s = np.maximum(duration_ms, 1.0) / 1000.0
    x = np.column_stack([
        df["Destination Port"].to_numpy(dtype=np.float64),
        duration_ms,
        packets,
        bytes_total,
        bytes_total / np.maximum(packets, 1),
        packets / duration_s,
        bytes_total / duration_s,
    ]).astype(np.float32)
    # Descarta filas corruptas (NaN/Inf) y duraciones negativas.
    mask = np.isfinite(x).all(axis=1) & (x[:, 1] >= 0)
    return x[mask], mask


def main() -> None:
    csvs = sorted(CSV_DIR.glob("*.csv"))
    if not csvs:
        raise SystemExit(f"No hay CSVs en {CSV_DIR} — ¿descomprimiste el dataset?")

    benign_parts: list[np.ndarray] = []
    attack_parts: list[np.ndarray] = []
    attack_labels: list[np.ndarray] = []

    for path in csvs:
        df = _read_csv(path)
        x, mask = _to_features(df)
        # Los CSVs de WebAttacks traen U+FFFD (mojibake del dataset original)
        # en labels como "Web Attack � Brute Force" — lo normalizamos a '-'.
        labels = df["Label"].str.strip().str.replace("�", "-").to_numpy()[mask]
        is_benign = labels == "BENIGN"
        benign_parts.append(x[is_benign])
        attack_parts.append(x[~is_benign])
        attack_labels.append(labels[~is_benign])
        print(
            f"  {path.name:58s} {is_benign.sum():>9,} benign  "
            f"{(~is_benign).sum():>8,} ataque"
        )

    benign = np.concatenate(benign_parts)
    attacks = np.concatenate(attack_parts)
    labels = np.concatenate(attack_labels)

    # Muestreo del benign para el archivo de entrenamiento.
    if len(benign) > BENIGN_SAMPLE:
        idx = RNG.choice(len(benign), BENIGN_SAMPLE, replace=False)
        benign = benign[idx]

    # Muestreo estratificado por tipo de ataque para validación.
    keep: list[np.ndarray] = []
    for label in np.unique(labels):
        rows = np.flatnonzero(labels == label)
        if len(rows) > ATTACK_SAMPLE_PER_LABEL:
            rows = RNG.choice(rows, ATTACK_SAMPLE_PER_LABEL, replace=False)
        keep.append(rows)
    keep_idx = np.concatenate(keep)
    attacks, labels = attacks[keep_idx], labels[keep_idx]

    np.savez_compressed(OUT_BENIGN, x=benign, feature_names=FEATURE_NAMES)
    np.savez_compressed(OUT_ATTACKS, x=attacks, labels=labels, feature_names=FEATURE_NAMES)

    # ASCII puro: la consola de Windows (cp1252) no soporta '✓'.
    print(f"\n[OK] {OUT_BENIGN.name}: {benign.shape[0]:,} flujos benignos")
    print(f"[OK] {OUT_ATTACKS.name}: {attacks.shape[0]:,} flujos de ataque")
    print("    Distribución de ataques para validación:")
    for label, count in zip(*np.unique(labels, return_counts=True)):
        print(f"      {label:30s} {count:>7,}")


if __name__ == "__main__":
    main()
