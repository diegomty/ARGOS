from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier

# Nombres de las 7 features 
FEATURES = ["dst_port", "duration_ms", "packets", "bytes",
            "bytes/paquete", "paquetes/s", "bytes/s"]


def featurize(flow: dict) -> list[float]:
    """Un flujo (dict) -> vector de 7 números. Misma fórmula que en producción."""
    pk = max(flow["packets"], 1)                     # piso de 1 para no dividir por 0
    dur_s = max(flow["duration_ms"], 1) / 1000.0     # piso de 1 ms
    return [
        flow["dst_port"],
        flow["duration_ms"],
        flow["packets"],
        flow["bytes"],
        flow["bytes"] / pk,                          # tamaño medio de paquete
        flow["packets"] / dur_s,                     # ritmo de paquetes
        flow["bytes"] / dur_s,                       # ritmo de datos
    ]


# ---------------------------------------------------------------------------
# 1) DATOS DE EJEMPLO  
#    label: 0 = normal   ·   1 = ataque
# ---------------------------------------------------------------------------
TRAIN = [
    # --- traffico NORMAL ----------------------------------------------------
    ("navegacion web",   {"dst_port": 443, "duration_ms": 4200, "packets": 31, "bytes": 15039}, 0),
    ("consulta DNS",     {"dst_port": 53,  "duration_ms": 14,   "packets": 2,  "bytes": 190},   0),
    ("descarga HTTP",    {"dst_port": 80,  "duration_ms": 9800, "packets": 120,"bytes": 148000},0),
    ("correo IMAPS",     {"dst_port": 993, "duration_ms": 6100, "packets": 44, "bytes": 23700}, 0),
    ("SSH interactivo",  {"dst_port": 22,  "duration_ms": 52000,"packets": 210,"bytes": 32000}, 0),
    ("actualizacion web",{"dst_port": 443, "duration_ms": 3100, "packets": 27, "bytes": 12800}, 0),
    # --- traffico de ATAQUE -------------------------------------------------
    ("port scan #1",     {"dst_port": 1090,"duration_ms": 1,    "packets": 2,  "bytes": 8},     1),
    ("port scan #2",     {"dst_port": 3306,"duration_ms": 1,    "packets": 2,  "bytes": 8},     1),
    ("port scan #3",     {"dst_port": 8080,"duration_ms": 1,    "packets": 1,  "bytes": 4},     1),
    ("SYN flood (DoS)",  {"dst_port": 80,  "duration_ms": 1,    "packets": 3,  "bytes": 120},   1),
    ("UDP flood (DoS)",  {"dst_port": 53,  "duration_ms": 1,    "packets": 4,  "bytes": 48},    1),
]


def main() -> None:
    # ---- 2) Flujos -> features -------------------------------------------
    print("=" * 78)
    print("PASO 1 y 2 - los flujos y su conversion a 7 numeros")
    print("=" * 78)
    print(f"{'ejemplo':18s}{'puerto':>7}{'dur':>6}{'pk':>4}{'bytes':>8}"
          f"{'B/pk':>7}{'pk/s':>8}{'etiqueta':>10}")
    X, y = [], []
    for nombre, flow, label in TRAIN:
        v = featurize(flow)
        X.append(v)
        y.append(label)
        print(f"{nombre:18s}{v[0]:>7.0f}{v[1]:>6.0f}{v[2]:>4.0f}{v[3]:>8.0f}"
              f"{v[4]:>7.1f}{v[5]:>8.0f}{'ATAQUE' if label else 'normal':>10}")

    X = np.array(X, dtype=float)
    y = np.array(y)
    print(f"\n  -> matriz de entrenamiento: {X.shape[0]} flujos x {X.shape[1]} features")
    print(f"  -> {int(y.sum())} ataques y {int((y == 0).sum())} normales")

    # ---- 3) Entrenamiento -------------------------------------------------
    print("\n" + "=" * 78)
    print("PASO 3 - entrenar el Random Forest (bosque de arboles que votan)")
    print("=" * 78)
    clf = RandomForestClassifier(n_estimators=50, random_state=42,
                                 class_weight="balanced")
    clf.fit(X, y)
    print("  modelo entrenado: 50 arboles de decision.")
    print("  (cada arbol aprende preguntas si/no sobre las 7 features)")

    # ---- 4) En qué se fija -----------------------------------------------
    print("\n" + "=" * 78)
    print("PASO 4 - en que se fijo el modelo (importancia de cada feature)")
    print("=" * 78)
    for nombre, imp in sorted(zip(FEATURES, clf.feature_importances_),
                              key=lambda t: -t[1]):
        barra = "#" * int(imp * 50)
        print(f"  {nombre:14s} {imp*100:5.1f}%  {barra}")

    # ---- 5) Predicción sobre flujos NUEVOS -------------------------------
    print("\n" + "=" * 78)
    print("PASO 5 - probar el modelo con flujos que NO vio al entrenar")
    print("=" * 78)
    NUEVOS = [
        ("web normal nueva", {"dst_port": 443, "duration_ms": 5000, "packets": 40, "bytes": 20000}),
        ("escaneo nuevo",    {"dst_port": 445, "duration_ms": 1,    "packets": 2,  "bytes": 8}),
        ("flood nuevo",      {"dst_port": 80,  "duration_ms": 1,    "packets": 5,  "bytes": 60}),
    ]
    for nombre, flow in NUEVOS:
        v = np.array([featurize(flow)])
        prob = clf.predict_proba(v)[0, 1]      # probabilidad de "ataque"
        veredicto = "ATAQUE" if prob >= 0.5 else "normal"
        print(f"  {nombre:18s} -> {veredicto:7s}  (confianza de ataque: {prob*100:4.0f}%)")

    print("\n  En ARGOS real, ese 'confianza de ataque' es el porcentaje de arboles")
    print("  que votaron 'ataque'. Si pasa de 50%, el flujo se marca.\n")


if __name__ == "__main__":
    main()
