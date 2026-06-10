"""Desglosa el veredicto del detector híbrido por modelo, para la demo.

Reproduce el estado del servidor (heredado + local entrenado con la DB) y
muestra, flujo de exfiltración por flujo, qué modelo lo marcó — para
atribuir la detección al modelo local adaptativo.
"""

from core.storage import Storage
from ml.detector import HybridDetector
from scripts.attack_sim import gen_exfil


def main() -> None:
    d = HybridDetector()
    d.retrain_local(Storage())  # misma ventana que usó el servidor al arrancar
    print("local ready:", d.local.ready, "\n")

    print(f'{"flujo exfil":>22s} | heredado | local | veredicto')
    print("-" * 64)
    solo_local = 0
    for f in gen_exfil("10.10.30.10", 8):
        v = d.evaluate(f)
        inh_hit = v["inherited"]["is_attack"]
        loc = v["local"]
        loc_hit = loc["is_anomaly"] if loc else False
        if loc_hit and not inh_hit:
            solo_local += 1
        mb = f["bytes"] / 1e6
        print(
            f'{mb:8.0f} MB / {f["packets"]:>6} pkts | '
            f'{("SI" if inh_hit else "no"):>7}  | '
            f'{("SI" if loc_hit else "no"):>4}  | '
            f'{",".join(v["detectors"]) or "-"}'
        )
    print("-" * 64)
    print(f"\nFlujos que SOLO el modelo local atrapo (heredado fallo): {solo_local}/8")
    print("-> esa es la inmunidad adquirida cubriendo lo que CICIDS no conoce.")


if __name__ == "__main__":
    main()
