"""Genera la documentación de Q-Sentinel en formato Word (.docx).

Produce un documento de portafolio que cubre el proyecto completo hasta la
Fase J (detector ML híbrido adaptativo), incluyendo arquitectura, fases,
detalle técnico del detector y los resultados de validación.

Uso:
    python -m scripts.gen_docs
    # -> docs/Q-Sentinel_Documentacion.docx
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "Q-Sentinel_Documentacion.docx"

CYAN = RGBColor(0x0E, 0x7C, 0x86)
DARK = RGBColor(0x1A, 0x1A, 0x2E)
RED = RGBColor(0xC0, 0x39, 0x2B)


def h_para(doc, text, size=11, bold=False, color=None, italic=False, after=6):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color
    p.paragraph_format.space_after = Pt(after)
    return p


def bullet(doc, text, bold_prefix=None):
    p = doc.add_paragraph(style="List Bullet")
    if bold_prefix:
        r = p.add_run(bold_prefix)
        r.bold = True
    p.add_run(text)
    return p


def add_table(doc, headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, htext in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = ""
        run = cell.paragraphs[0].add_run(htext)
        run.bold = True
        run.font.size = Pt(9)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            run = cells[i].paragraphs[0].add_run(str(val))
            run.font.size = Pt(9)
    doc.add_paragraph()
    return t


def build() -> None:
    doc = Document()

    # Estilo base
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)

    # --- Portada ---
    for _ in range(6):
        doc.add_paragraph()
    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = title.add_run("Q-SENTINEL")
    r.bold = True
    r.font.size = Pt(40)
    r.font.color.rgb = CYAN

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("Inmunidad Digital Adaptativa")
    r.font.size = Pt(18)
    r.font.color.rgb = DARK

    desc = doc.add_paragraph()
    desc.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = desc.add_run("Plataforma de visualización SOC con detección de anomalías,\n"
                     "respuesta autónoma y gemelo digital 3D")
    r.italic = True
    r.font.size = Pt(12)

    for _ in range(10):
        doc.add_paragraph()
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta.add_run(f"Documentación técnica · {date.today().strftime('%d/%m/%Y')}\n"
                 "Autor: Juan Diego · github.com/diegomty/Q-Sentinel")
    doc.add_page_break()

    # --- 1. Resumen ejecutivo ---
    doc.add_heading("1. Resumen ejecutivo", level=1)
    h_para(doc,
        "Q-Sentinel es una plataforma de visualización para Centro de Operaciones de "
        "Seguridad (SOC) que materializa el concepto de «inmunidad digital adaptativa»: "
        "un sistema que detecta amenazas, responde de forma autónoma y aprende de su "
        "propia red, presentando todo en un gemelo digital 3D interactivo.")
    h_para(doc,
        "El proyecto evolucionó de un simple monitor de syslog a una plataforma completa "
        "que combina detección estadística (entropía de Shannon), integridad forense "
        "(SHA-3-256), respuesta automática vía SSH sobre Cisco IOS, ingesta de flujos "
        "NetFlow v9, persistencia en SQLite y, en su fase más reciente, un detector de "
        "Machine Learning híbrido que reemplaza los umbrales fijos por modelos adaptativos.")

    # --- 2. Concepto ---
    doc.add_heading("2. Concepto: la metáfora inmunológica", level=1)
    h_para(doc,
        "El diseño se inspira en el sistema inmunológico humano, que combina dos tipos "
        "de defensa:")
    bullet(doc, "reconoce patógenos conocidos heredados evolutivamente. En Q-Sentinel, "
                "el modelo entrenado con el dataset CICIDS2017 cumple este papel: reconoce "
                "patrones de ataque clásicos desde el primer día.",
           bold_prefix="Inmunidad heredada — ")
    bullet(doc, "aprende de la exposición a antígenos propios. El modelo local de "
                "Q-Sentinel aprende la «normalidad» de la red específica y detecta "
                "desviaciones, incluyendo amenazas nunca antes vistas.",
           bold_prefix="Inmunidad adquirida — ")
    h_para(doc,
        "Esta dualidad es la que da nombre al proyecto y justifica la arquitectura del "
        "detector híbrido descrito en la sección 6.")

    # --- 3. Arquitectura ---
    doc.add_heading("3. Arquitectura del sistema", level=1)
    h_para(doc,
        "Q-Sentinel corre como un único proceso Python (FastAPI) que orquesta varios "
        "hilos de captura y sirve un frontend web con visualización 3D. El flujo de datos "
        "de extremo a extremo es:")
    h_para(doc,
        "Cisco IOS  →  [syslog UDP/514 + NetFlow UDP/2055]  →  listeners en hilos daemon  "
        "→  análisis (entropía / ML)  →  persistencia SQLite  →  broadcast WebSocket  →  "
        "gemelo digital 3D (Three.js)",
        italic=True, color=CYAN)
    h_para(doc, "Componentes principales:", bold=True, after=2)
    add_table(doc,
        ["Módulo", "Responsabilidad"],
        [
            ["core/analysis.py", "Entropía de Shannon, hash SHA-3-256, heurística de confianza"],
            ["core/responder.py", "Respuesta autónoma vía SSH (Paramiko) sobre Cisco IOS"],
            ["core/flowlistener.py", "Parser NetFlow v9 propio (RFC 3954)"],
            ["core/storage.py", "Persistencia SQLite (WAL) de eventos, flujos y aislamientos"],
            ["core/topology.py", "Modelo lógico de la red desde topology.yaml"],
            ["ml/", "Detector híbrido: features, modelos heredado y local, inferencia"],
            ["server.py", "FastAPI: WebSocket, API REST, orquestación de hilos"],
            ["web/", "Gemelo digital 3D, dashboard, gráficas (Three.js + vanilla JS)"],
        ])

    # --- 4. Fases ---
    doc.add_heading("4. Fases del proyecto", level=1)
    add_table(doc,
        ["Fase", "Entregable", "Estado"],
        [
            ["A–E", "Núcleo modular: entropía + SHA-3, respuesta SSH autónoma", "Completado"],
            ["F", "Servidor FastAPI + WebSocket (envelope {kind, payload})", "Completado"],
            ["G", "Gemelo digital 3D con Three.js (membrana, etiquetas, flujos)", "Completado"],
            ["H", "Touch-to-isolate: aislamiento de segmentos vía SSH", "Completado"],
            ["I", "Ingesta NetFlow v9 + persistencia SQLite + gráfica de entropía", "Completado"],
            ["J", "Detector ML híbrido adaptativo (CICIDS + línea base local)", "Completado"],
            ["K", "DPI con Scapy (opcional)", "Futuro"],
        ])

    # --- 5. Detección estadística (fundamento) ---
    doc.add_heading("5. Detección estadística: el fundamento", level=1)
    h_para(doc,
        "Antes del ML, Q-Sentinel detectaba anomalías midiendo la entropía de Shannon de "
        "cada mensaje syslog. La entropía H(X) = -Σ P(xi)·log2 P(xi) cuantifica el "
        "«desorden» de un mensaje: texto estructurado y repetitivo tiene baja entropía; "
        "inyecciones, payloads codificados o datos aleatorios la elevan.")
    h_para(doc,
        "Cada mensaje se sella además con un hash SHA-3-256, formando una cadena de "
        "integridad forense post-cuántica. La limitación de este enfoque —un umbral fijo "
        "(H > 5.0) que no se adapta a la red— es precisamente lo que resuelve la Fase J.")

    # --- 6. Fase J: detector híbrido ---
    doc.add_heading("6. Fase J: detector ML híbrido adaptativo", level=1)

    doc.add_heading("6.1 El problema del umbral fijo", level=2)
    h_para(doc,
        "Un umbral fijo de entropía genera falsos positivos con tráfico legítimo inusual "
        "y falsos negativos con ataques de baja entropía. No conoce la red que protege ni "
        "evoluciona con ella. La solución: reemplazarlo por modelos que aprenden.")

    doc.add_heading("6.2 Las 7 features compartidas", level=2)
    h_para(doc,
        "Toda la capa ML opera sobre un vector común de 7 features derivadas de cada "
        "flujo, construido de forma idéntica desde tres orígenes (CSVs de CICIDS, tabla "
        "flows y flujos NetFlow en vivo) mediante ml/features.py:")
    add_table(doc,
        ["Feature", "Descripción"],
        [
            ["dst_port", "Puerto destino (la más discriminante: 0.281 de importancia)"],
            ["duration_ms", "Duración del flujo (LAST_SWITCHED − FIRST_SWITCHED)"],
            ["packets", "Total de paquetes del flujo"],
            ["bytes", "Total de bytes del flujo"],
            ["bytes_per_packet", "Tamaño medio de paquete"],
            ["packets_per_s", "Tasa de paquetes (firma de floods/DoS)"],
            ["bytes_per_s", "Tasa de bytes (firma de exfiltración)"],
        ])
    h_para(doc,
        "Captar duration_ms exigió extender el parser NetFlow para leer los campos "
        "FIRST/LAST_SWITCHED (tipos 22 y 21 del RFC 3954) y añadir una columna a SQLite "
        "con migración aditiva idempotente.")

    doc.add_heading("6.3 Modelo heredado (supervisado, CICIDS2017)", level=2)
    h_para(doc,
        "Entrenado con el dataset CICIDS2017 (2.8 millones de flujos etiquetados de la "
        "Universidad de New Brunswick). Un hallazgo clave durante el desarrollo: un "
        "Isolation Forest no supervisado detectaba menos del 1 % de los ataques, porque "
        "un flujo de port scan o DoS individual no es un «outlier» —se parece a un flujo "
        "benigno pequeño—. La frontera ataque/benigno solo es visible con las etiquetas, "
        "así que se optó por un RandomForest supervisado.")
    h_para(doc, "Resultados de validación (holdout 25 % nunca visto):", bold=True, after=2)
    add_table(doc,
        ["Métrica", "Valor"],
        [
            ["Detección global de ataques", "98.03 %"],
            ["Falsos positivos", "0.96 %"],
            ["DDoS / PortScan / DoS / fuerza bruta", "> 98 %"],
            ["Web Attacks / Infiltration (nivel de flujo)", "40–67 % (limitación esperada)"],
        ])

    doc.add_heading("6.4 Modelo local adaptativo (Isolation Forest)", level=2)
    h_para(doc,
        "Esta es la mitad «adaptativa». Un Isolation Forest entrenado exclusivamente con "
        "el tráfico de la propia red (tabla flows), con ventana móvil de 7 días y "
        "re-entrenamiento periódico. No sabe nada de ataques: marca como anómalo lo que se "
        "desvía de la línea base local, cubriendo amenazas que CICIDS nunca vio. Si la "
        "ventana tiene menos de 200 flujos, el modelo se abstiene (mejor sin opinión que "
        "una opinión sin base estadística).")

    doc.add_heading("6.5 Veredicto híbrido", level=2)
    h_para(doc,
        "Cada flujo pasa por ambos modelos. El veredicto es la unión lógica (OR): se marca "
        "como anómalo si cualquiera de los dos lo señala, e incluye la atribución de qué "
        "detector lo marcó y con qué confianza. El sistema degrada con gracia: sin modelo "
        "heredado opina solo el local, y viceversa.")

    # --- 7. Validación ---
    doc.add_heading("7. Validación de extremo a extremo", level=1)
    h_para(doc,
        "Para validar el detector sin depender de tráfico de laboratorio escaso, se "
        "construyeron simuladores que inyectan NetFlow v9 real al colector (UDP/2055), "
        "ejerciendo el pipeline completo: parser → deduplicación → featurización → "
        "detector → broadcast → visualización. Los valores de cada ataque se calibraron "
        "con las distribuciones reales medidas del propio CICIDS2017.")
    h_para(doc, "Ataque multi-etapa contra el departamento crítico (PC-TI-01):",
           bold=True, after=2)
    add_table(doc,
        ["Etapa", "Flujos", "Detección"],
        [
            ["Recon (port scan)", "60", "~67 %"],
            ["DDoS (botnet externa)", "80", "~88 %"],
            ["Fuerza bruta SSH", "50", "~78 %"],
            ["Exfiltración (50 MB)", "6", "atrapada por modelo local"],
        ])
    h_para(doc,
        "Resultado global: 141 de 218 flujos marcados, 0 errores de parseo.")

    doc.add_heading("7.1 La prueba estrella: el sistema adaptativo en acción", level=2)
    h_para(doc,
        "Tras construir la línea base local con 300 flujos de tráfico normal, se relanzó "
        "la exfiltración. El desglose por detector demostró el valor de la arquitectura "
        "híbrida: 2 de cada 8 exfiltraciones fueron atrapadas ÚNICAMENTE por el modelo "
        "local, porque ese patrón (transferencia masiva a puerto 4444) no existe en "
        "CICIDS2017. La inmunidad adquirida cubriendo exactamente lo que la heredada "
        "desconoce —la tesis central del proyecto, demostrada empíricamente.")

    # --- 8. Stack ---
    doc.add_heading("8. Stack tecnológico", level=1)
    add_table(doc,
        ["Capa", "Tecnologías"],
        [
            ["Backend", "Python, FastAPI, Uvicorn, WebSockets, asyncio + threading"],
            ["ML", "scikit-learn (RandomForest, IsolationForest), pandas, NumPy"],
            ["Red", "Paramiko (SSH), NetFlow v9 (parser propio), syslog"],
            ["Persistencia", "SQLite (modo WAL)"],
            ["Frontend", "Three.js, CSS2DRenderer, JavaScript vanilla (ES modules)"],
            ["Infra/Lab", "EVE-NG, Cisco IOS 7200, IOSvL2, VPCS"],
        ])

    # --- 9. Limitaciones ---
    doc.add_heading("9. Limitaciones conocidas y trabajo futuro", level=1)
    bullet(doc, "La detección por flujo individual tiene un techo: un port scan se "
                "reconoce mejor como patrón agregado que flujo a flujo.")
    bullet(doc, "Envenenamiento de la línea base: un atacante paciente que genere tráfico "
                "malicioso sostenido podría hacer que el modelo local lo asimile como "
                "normal. Se observó que con la base contaminada la detección de exfil "
                "bajó de 20/20 a 11/20.")
    bullet(doc, "Ataques a nivel de contenido (SQLi, XSS) son invisibles a nivel de flujo; "
                "requerirían inspección profunda de paquetes (DPI, Fase K).")
    bullet(doc, "Trabajo futuro: DPI con Scapy, adaptador SOAR para Fortinet/Palo Alto, "
                "contenerización con Docker.")

    # --- 10. Ejecución ---
    doc.add_heading("10. Cómo ejecutar", level=1)
    h_para(doc, "Preparar el modelo heredado (una vez):", bold=True, after=2)
    h_para(doc, "python -m ml.prepare_cicids    # extrae features de CICIDS2017\n"
                "python -m ml.train             # entrena el RandomForest",
           italic=True, color=DARK)
    h_para(doc, "Arrancar el servidor:", bold=True, after=2)
    h_para(doc, "python server.py               # frontend en http://localhost:8000",
           italic=True, color=DARK)
    h_para(doc, "Validar el detector (con el servidor corriendo):", bold=True, after=2)
    h_para(doc, "python -m scripts.traffic_sim --flows 300   # tráfico normal\n"
                "python -m scripts.attack_sim --attack all    # ataque multi-etapa\n"
                "python -m scripts.demo_breakdown             # desglose por detector",
           italic=True, color=DARK)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)
    print(f"[OK] documento generado: {OUT.relative_to(ROOT)}")
    print(f"     {OUT.stat().st_size // 1024} KB")


if __name__ == "__main__":
    build()
