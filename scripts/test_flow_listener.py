"""Smoke test del listener NetFlow — corre indefinido, Ctrl+C para parar.

Uso:
    python scripts/test_flow_listener.py

Mientras corre, abre otra terminal y desde la consola del VPCS FINANZAS:
    ping 10.10.20.10 -c 5

Espera ~20s y deberías ver flujos parseados.
"""

import sys
import time
from pathlib import Path

# Permite ejecutar desde la raíz del proyecto sin instalar como package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.flowlistener import FlowListener


def main() -> None:
    count = 0

    def on_flow(f):
        nonlocal count
        count += 1
        print(
            f"[#{count:03d}] {f['src_ip']:>15s}:{f['src_port']:<5d} "
            f"-> {f['dst_ip']:>15s}:{f['dst_port']:<5d} "
            f"proto={f['protocol']:<4s} pkts={f['packets']:>4d} "
            f"bytes={f['bytes']:>6d} (de exporter {f['exporter']})",
            flush=True,
        )

    listener = FlowListener(host="0.0.0.0", port=2055)
    listener.start(on_flow)
    print(">>> listener UDP/2055 activo. Genera trafico desde el lab.", flush=True)
    print(">>> Ctrl+C para parar.", flush=True)

    try:
        last_stat_t = time.time()
        while True:
            time.sleep(1)
            # Heartbeat cada 10s con stats detalladas
            if time.time() - last_stat_t >= 10:
                s = listener.stats()
                print(
                    f"... heartbeat | UDP pkts: {s['packets']} | flowsets: {s['flowsets']} | "
                    f"templates: {s['templates']} | flujos: {s['flows']} | errores: {s['parse_errors']}",
                    flush=True,
                )
                last_stat_t = time.time()
    except KeyboardInterrupt:
        print("\n>>> deteniendo listener...", flush=True)
    finally:
        listener.stop()
        print(f">>> stats finales: {listener.stats()}", flush=True)


if __name__ == "__main__":
    main()
