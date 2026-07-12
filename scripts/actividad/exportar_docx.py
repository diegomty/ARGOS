"""Convierte el documento de respuestas (Markdown) a Word (.docx).

Usa pandoc embebido vía pypandoc-binary — no requiere instalación manual.
Preserva tablas, encabezados, listas y bloques de código.

Uso:
    python scripts/actividad/exportar_docx.py
"""

from pathlib import Path

import pypandoc

CARPETA = Path(__file__).resolve().parent
ENTRADA = CARPETA / "actividad_respuestas.md"
SALIDA = CARPETA / "actividad_respuestas.docx"


def main() -> None:
    if not ENTRADA.exists():
        raise SystemExit(f"[!] No encuentro {ENTRADA}")

    pypandoc.convert_file(
        str(ENTRADA),
        to="docx",
        outputfile=str(SALIDA),
        extra_args=[
            "--standalone",
            "--from=gfm+pipe_tables+yaml_metadata_block",
        ],
    )
    print(f"[OK] Documento Word generado: {SALIDA}")


if __name__ == "__main__":
    main()
