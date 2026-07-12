"""Demo de integridad post-cuántica (SHA-3-256) sobre la cadena de logs
de Q-Sentinel.

Toma un evento real persistido en qsentinel.db, muestra su hash almacenado
en el momento de la captura, simula una manipulación del mensaje (cambia
un solo carácter), recalcula el hash y demuestra que no coincide.

Eso es la base técnica de cualquier firma digital: el hash actúa como
huella unívoca; cualquier modificación, por mínima que sea, lo invalida.

Uso (desde c:\\dev\\Sentinel con venv activado):
    python scripts/actividad/demo_integridad.py
"""

import hashlib
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[2] / "qsentinel.db"


def sha3(texto: str) -> str:
    return hashlib.sha3_256(texto.encode("utf-8")).hexdigest()


def main() -> None:
    if not DB.exists():
        raise SystemExit(f"[!] No encuentro {DB}")

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    # Tomamos un evento anómalo reciente del bloque sospechoso (185.32.44.10).
    row = conn.execute(
        """
        SELECT id, ts, raw_message, sha3, entropy, is_anomaly
        FROM events
        WHERE is_anomaly = 1 AND raw_message LIKE '%185.32.44.10%'
        ORDER BY received_at DESC
        LIMIT 1
        """
    ).fetchone()
    conn.close()

    if row is None:
        raise SystemExit("[!] No hay eventos anómalos del bloque 1 en la BD.")

    original = row["raw_message"]
    hash_almacenado = row["sha3"]
    hash_recalculado = sha3(original)

    print("=" * 78)
    print("FASE 1 — VERIFICACIÓN DE INTEGRIDAD DEL EVENTO ORIGINAL")
    print("=" * 78)
    print(f"id evento         : {row['id']}")
    print(f"timestamp         : {row['ts']}")
    print(f"entropía          : {row['entropy']:.4f} bits")
    print(f"mensaje original  : {original}")
    print(f"hash almacenado   : {hash_almacenado}")
    print(f"hash recalculado  : {hash_recalculado}")
    if hash_almacenado == hash_recalculado:
        print("✅ COINCIDEN — el evento no ha sido alterado desde su captura.")
    else:
        print("❌ NO COINCIDEN — la BD ya fue manipulada.")
    print()

    # --- Simulación de manipulación ---
    # Cambiamos UN solo carácter en el mensaje. El cambio es semánticamente
    # mínimo (cambiar "root" por "r0ot") pero criptográficamente catastrófico:
    # el hash resultante no se parece en nada al original.
    manipulado = original.replace("root", "r0ot", 1).replace("admin", "admln", 1)
    if manipulado == original:
        # Si el evento no tenía esos tokens, hacemos un cambio neutral.
        manipulado = original[:-1] + ("X" if not original.endswith("X") else "Y")

    hash_manipulado = sha3(manipulado)

    print("=" * 78)
    print("FASE 2 — SIMULACIÓN DE MANIPULACIÓN POST-CAPTURA")
    print("=" * 78)
    print("Un atacante con acceso a la BD intenta encubrir su rastro alterando")
    print("el mensaje (sustitución 'root'→'r0ot' / 'admin'→'admln').")
    print()
    print(f"mensaje manipulado: {manipulado}")
    print(f"hash original     : {hash_almacenado}")
    print(f"hash tras tampering: {hash_manipulado}")

    if hash_almacenado == hash_manipulado:
        print("⚠️  imposible — los hashes nunca coinciden tras una alteración.")
    else:
        # Cuántos caracteres del hash hex coinciden por azar
        coincidentes = sum(1 for a, b in zip(hash_almacenado, hash_manipulado) if a == b)
        print()
        print(f"❌ DETECTADO — los hashes no coinciden.")
        print(f"   Coincidencias hex por azar: {coincidentes}/64 caracteres.")
        print(f"   Un cambio de 1-2 caracteres en el mensaje altera ~el 50% del hash.")
        print()
        print("   Conclusión: cualquier modificación post-captura es matemáticamente")
        print("   detectable comparando contra el hash almacenado en la cadena de")
        print("   custodia. SHA-3-256 garantiza esto incluso frente a adversarios")
        print("   con computación cuántica (resistencia post-cuántica).")


if __name__ == "__main__":
    main()
