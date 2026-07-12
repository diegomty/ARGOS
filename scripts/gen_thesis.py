"""Genera la documentación EXTENSA tipo tesis de Q-Sentinel en Word (.docx).

A diferencia de scripts/gen_docs.py (resumen ejecutivo de ~10 páginas), este
script produce un documento académico extenso, con portada, índice automático,
marco teórico a fondo, metodología, diseño e implementación detallados,
resultados de validación, conclusiones, referencias y anexos.

Uso:
    python -m scripts.gen_thesis
    # -> docs/Q-Sentinel_Tesis.docx
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "Q-Sentinel_Tesis.docx"

CYAN = RGBColor(0x0E, 0x7C, 0x86)
DARK = RGBColor(0x1A, 0x1A, 0x2E)
GREY = RGBColor(0x44, 0x4A, 0x55)
CODE = RGBColor(0x10, 0x2A, 0x33)


# ---------------------------------------------------------------- helpers ----

def para(doc, text, size=11, bold=False, italic=False, color=None,
         align=None, after=8, before=0):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if color:
        run.font.color.rgb = color
    if align:
        p.alignment = align
    p.paragraph_format.space_after = Pt(after)
    p.paragraph_format.space_before = Pt(before)
    return p


def bullet(doc, text, bold_prefix=None):
    p = doc.add_paragraph(style="List Bullet")
    if bold_prefix:
        p.add_run(bold_prefix).bold = True
    p.add_run(text)
    return p


def numbered(doc, text, bold_prefix=None):
    p = doc.add_paragraph(style="List Number")
    if bold_prefix:
        p.add_run(bold_prefix).bold = True
    p.add_run(text)
    return p


def code_block(doc, text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Pt(14)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after = Pt(10)
    lines = text.strip("\n").split("\n")
    for i, line in enumerate(lines):
        run = p.add_run(line + ("\n" if i < len(lines) - 1 else ""))
        run.font.name = "Consolas"
        run.font.size = Pt(9)
        run.font.color.rgb = CODE
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), "EEF1F4")
    p._p.get_or_add_pPr().append(shd)
    return p


def table(doc, headers, rows):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Light Grid Accent 1"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        r = c.paragraphs[0].add_run(h)
        r.bold = True
        r.font.size = Pt(9)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ""
            r = cells[i].paragraphs[0].add_run(str(val))
            r.font.size = Pt(9)
    doc.add_paragraph()
    return t


def page_break(doc):
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def add_toc(doc):
    p = doc.add_paragraph()
    run = p.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = 'TOC \\o "1-3" \\h \\z \\u'
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    placeholder = OxmlElement("w:t")
    placeholder.text = "Haz clic derecho aquí y elige «Actualizar campos» (o presiona F9) para generar el índice."
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    for el in (begin, instr, sep, placeholder, end):
        run._r.append(el)


def h1(doc, text):
    doc.add_heading(text, level=1)


def h2(doc, text):
    doc.add_heading(text, level=2)


def h3(doc, text):
    doc.add_heading(text, level=3)


# ------------------------------------------------------------------ build ----

def build() -> None:
    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(11)
    normal.paragraph_format.space_after = Pt(8)

    _cover(doc)
    page_break(doc)
    _abstract(doc)
    page_break(doc)
    _toc_page(doc)
    page_break(doc)

    _cap1_introduccion(doc)
    page_break(doc)
    _cap2_marco_teorico(doc)
    page_break(doc)
    _cap3_estado_arte(doc)
    page_break(doc)
    _cap4_arquitectura(doc)
    page_break(doc)
    _cap5_implementacion(doc)
    page_break(doc)
    _cap6_detector_ml(doc)
    page_break(doc)
    _cap7_digital_twin(doc)
    page_break(doc)
    _cap8_validacion(doc)
    page_break(doc)
    _cap9_limitaciones(doc)
    page_break(doc)
    _cap10_conclusiones(doc)
    page_break(doc)
    _referencias(doc)
    page_break(doc)
    _anexos(doc)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)
    n_head = sum(1 for p in doc.paragraphs if p.style.name.startswith("Heading"))
    print(f"[OK] tesis generada: {OUT.relative_to(ROOT)}")
    print(f"     {OUT.stat().st_size // 1024} KB · {len(doc.paragraphs)} parrafos · "
          f"{n_head} encabezados · {len(doc.tables)} tablas")


def _cover(doc):
    for _ in range(4):
        doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Q-SENTINEL"); r.bold = True; r.font.size = Pt(44); r.font.color.rgb = CYAN
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Inmunidad Digital Adaptativa"); r.font.size = Pt(20); r.font.color.rgb = DARK
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Plataforma de visualización SOC con detección de anomalías por\n"
                  "entropía y aprendizaje automático, respuesta autónoma sobre\n"
                  "infraestructura Cisco y gemelo digital tridimensional")
    r.italic = True; r.font.size = Pt(13); r.font.color.rgb = GREY
    for _ in range(6):
        doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("Documentación técnica integral del proyecto"); r.font.size = Pt(12); r.bold = True
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run("Área: Ciberseguridad y Defensa de Redes").font.size = Pt(11)
    for _ in range(5):
        doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run(f"Autor: Juan Diego\nRepositorio: github.com/diegomty/Q-Sentinel\n"
              f"Fecha: {date.today().strftime('%d/%m/%Y')} · Versión del documento 1.0").font.size = Pt(11)


def _abstract(doc):
    h1(doc, "Resumen")
    para(doc,
        "Q-Sentinel es una plataforma de visualización y respuesta para Centros de "
        "Operaciones de Seguridad (SOC) que materializa el concepto de «inmunidad digital "
        "adaptativa»: un sistema capaz de detectar amenazas en la red, responder de forma "
        "autónoma sobre la infraestructura afectada y, sobre todo, aprender de su propio "
        "tráfico para reconocer lo que se desvía de la normalidad. El proyecto parte de un "
        "monitor de syslog basado en la entropía de Shannon y evoluciona, a lo largo de diez "
        "fases de desarrollo, hasta convertirse en una plataforma completa que integra "
        "ingesta de flujos NetFlow v9, persistencia en base de datos, respuesta automática "
        "vía SSH sobre routers Cisco IOS, un gemelo digital tridimensional interactivo y, en "
        "su fase más avanzada, un detector de anomalías basado en aprendizaje automático "
        "híbrido.")
    para(doc,
        "El aporte central de este trabajo es el detector híbrido que combina dos modelos "
        "complementarios: un clasificador supervisado entrenado con el conjunto de datos "
        "público CICIDS2017 —que reconoce patrones de ataque conocidos con una tasa de "
        "detección del 98 %— y un modelo no supervisado de detección de anomalías (Isolation "
        "Forest) entrenado con el tráfico propio de la red, que se re-entrena periódicamente "
        "y detecta desviaciones novedosas. Esta dualidad reproduce la metáfora del sistema "
        "inmunológico: memoria heredada más inmunidad adquirida. La validación experimental, "
        "realizada mediante inyección de tráfico NetFlow sintético calibrado con distribuciones "
        "reales, demuestra empíricamente que el modelo local captura ataques (por ejemplo, "
        "exfiltración de datos) que el modelo heredado desconoce.")
    para(doc, "Palabras clave: ", bold=True, after=2)
    para(doc,
        "SOC, detección de anomalías, entropía de Shannon, SHA-3, aprendizaje automático, "
        "Isolation Forest, Random Forest, NetFlow, Cisco IOS, SSH, gemelo digital, Three.js, "
        "FastAPI, respuesta autónoma, CICIDS2017.", italic=True)

    h2(doc, "Abstract")
    para(doc,
        "Q-Sentinel is a visualization and response platform for Security Operations Centers "
        "(SOC) that embodies the concept of «adaptive digital immunity»: a system able to "
        "detect network threats, autonomously respond on the affected infrastructure and, most "
        "importantly, learn from its own traffic to recognize deviations from normal behavior. "
        "The project starts as a syslog monitor based on Shannon entropy and evolves, across "
        "ten development phases, into a full platform integrating NetFlow v9 flow ingestion, "
        "database persistence, automatic SSH response over Cisco IOS routers, an interactive "
        "3D digital twin and, in its most advanced phase, a hybrid machine-learning anomaly "
        "detector. The central contribution is a hybrid detector combining a supervised "
        "classifier trained on the public CICIDS2017 dataset (98 % detection rate) with an "
        "unsupervised Isolation Forest trained on the network's own traffic, periodically "
        "retrained, which detects novel deviations — reproducing the immune-system metaphor of "
        "inherited memory plus acquired immunity.")


def _toc_page(doc):
    h1(doc, "Índice")
    add_toc(doc)


def _cap1_introduccion(doc):
    h1(doc, "Capítulo 1. Introducción")

    h2(doc, "1.1 Contexto")
    para(doc,
        "Las redes corporativas modernas generan un volumen de eventos de seguridad que "
        "supera con creces la capacidad de análisis manual. Un Centro de Operaciones de "
        "Seguridad (SOC) recibe miles de registros por minuto provenientes de firewalls, "
        "routers, switches, servidores y estaciones de trabajo. La detección temprana de una "
        "intrusión depende de la capacidad de separar, en ese torrente de datos, los eventos "
        "verdaderamente anómalos del ruido operativo cotidiano. Históricamente esta tarea se "
        "ha apoyado en reglas y firmas estáticas: patrones conocidos de ataque que un motor "
        "compara contra cada evento. El problema de este enfoque es doble: no reconoce "
        "amenazas nuevas para las que no existe firma, y no se adapta a las particularidades "
        "de cada red, generando falsos positivos con tráfico legítimo pero inusual.")
    para(doc,
        "Q-Sentinel nace como un ejercicio para explorar una alternativa: un sistema que, "
        "además de reconocer patrones conocidos, aprenda de manera continua qué es «normal» "
        "en la red que protege, y que presente toda esta información no como una lista plana "
        "de alertas, sino como un organismo vivo visualizado en tres dimensiones. La metáfora "
        "rectora es biológica —el sistema inmunológico— y da nombre al concepto que vertebra "
        "el proyecto: la inmunidad digital adaptativa.")

    h2(doc, "1.2 Planteamiento del problema")
    para(doc,
        "El problema que aborda este trabajo puede enunciarse en tres dimensiones "
        "interrelacionadas:")
    bullet(doc, "los sistemas basados en umbrales fijos y firmas no se "
        "adaptan a la red concreta que vigilan, produciendo tanto falsos positivos "
        "(tráfico legítimo marcado como amenaza) como falsos negativos (ataques de bajo "
        "perfil que no superan el umbral).", bold_prefix="Detección rígida — ")
    bullet(doc, "detectar una amenaza tiene poco valor si la respuesta "
        "depende de la intervención manual de un operador que puede tardar minutos u horas. "
        "Se requiere capacidad de respuesta automática sobre la infraestructura.",
        bold_prefix="Respuesta lenta — ")
    bullet(doc, "los paneles tradicionales de un SOC son listas y "
        "gráficas bidimensionales que dificultan comprender la topología afectada y la "
        "propagación espacial de un incidente.", bold_prefix="Comprensión limitada — ")

    h2(doc, "1.3 Justificación")
    para(doc,
        "La relevancia del proyecto se sostiene en tres pilares. En lo técnico, integra en "
        "una sola plataforma coherente un conjunto de disciplinas que suelen tratarse por "
        "separado: teoría de la información, criptografía, automatización de redes, "
        "aprendizaje automático y visualización tridimensional. En lo formativo, constituye "
        "un vehículo para aplicar de forma práctica conceptos de ciberseguridad y redes "
        "sobre un laboratorio realista. En lo profesional, produce un artefacto de portafolio "
        "que demuestra competencias de extremo a extremo, desde el análisis de paquetes de "
        "bajo nivel hasta el diseño de interfaces.")

    h2(doc, "1.4 Objetivos")
    h3(doc, "1.4.1 Objetivo general")
    para(doc,
        "Diseñar e implementar una plataforma de visualización y respuesta para SOC que "
        "detecte anomalías en la red combinando análisis estadístico y aprendizaje automático "
        "adaptativo, responda de forma autónoma sobre infraestructura Cisco y represente el "
        "estado de la red en un gemelo digital tridimensional interactivo.")
    h3(doc, "1.4.2 Objetivos específicos")
    numbered(doc, "Implementar un motor de detección de anomalías basado en la entropía de "
        "Shannon sobre mensajes de syslog, con sellado de integridad mediante SHA-3-256.")
    numbered(doc, "Construir un mecanismo de respuesta autónoma que, ante una amenaza "
        "correlacionada, aplique contramedidas sobre el router Cisco vía SSH.")
    numbered(doc, "Desarrollar un parser propio de NetFlow v9 para ingerir y caracterizar los "
        "flujos de red del laboratorio.")
    numbered(doc, "Diseñar un modelo de detección híbrido que combine un clasificador "
        "supervisado (patrones conocidos) con un modelo no supervisado adaptativo (línea base "
        "local).")
    numbered(doc, "Implementar un gemelo digital tridimensional que visualice la topología, "
        "los flujos y las anomalías en tiempo real.")
    numbered(doc, "Validar experimentalmente el sistema mediante la simulación de ataques y la "
        "medición de las tasas de detección.")

    h2(doc, "1.5 Alcance y limitaciones del alcance")
    para(doc,
        "El proyecto se desarrolla y valida sobre un laboratorio virtualizado en EVE-NG que "
        "reproduce una red corporativa segmentada por departamentos. El sistema opera sobre "
        "tráfico IPv4 y sobre la variante de NetFlow v9 exportada por Cisco IOS. La respuesta "
        "autónoma se implementa para Cisco IOS; la generalización a otros fabricantes se "
        "plantea como trabajo futuro. El detector de contenido a nivel de paquete (inspección "
        "profunda) queda fuera del alcance de la versión documentada y se propone como "
        "extensión.")

    h2(doc, "1.6 Metodología de desarrollo")
    para(doc,
        "El desarrollo siguió un enfoque incremental por fases, cada una de las cuales añade "
        "una capacidad verificable sobre la anterior. Se adoptó una arquitectura modular que "
        "permitió validar cada componente de forma aislada antes de integrarlo. Las diez "
        "fases (A a J) se resumen en el Capítulo 4 y se detallan a lo largo del documento.")


def _cap2_marco_teorico(doc):
    h1(doc, "Capítulo 2. Marco teórico")

    h2(doc, "2.1 La metáfora inmunológica")
    para(doc,
        "El sistema inmunológico de los vertebrados combina dos mecanismos de defensa. La "
        "inmunidad innata (heredada) reconoce patrones moleculares asociados a patógenos "
        "conocidos evolutivamente y actúa de inmediato. La inmunidad adaptativa (adquirida) "
        "aprende de la exposición a antígenos concretos, genera anticuerpos específicos y "
        "conserva memoria de ellos. Q-Sentinel traslada esta dualidad al dominio de la "
        "ciberseguridad: un modelo entrenado con un corpus público de ataques cumple el papel "
        "de inmunidad heredada, mientras que un modelo entrenado con el tráfico propio de la "
        "red cumple el de inmunidad adquirida. Esta analogía no es meramente estética: "
        "justifica arquitectónicamente por qué se necesitan dos modelos y no uno.")

    h2(doc, "2.2 Entropía de Shannon")
    para(doc,
        "La entropía de Shannon cuantifica la incertidumbre o el «desorden» de una fuente de "
        "información. Para un mensaje considerado como una secuencia de caracteres, se define "
        "sobre la distribución de frecuencias de sus símbolos:")
    para(doc, "H(X) = − Σ P(xᵢ) · log₂ P(xᵢ)", align=WD_ALIGN_PARAGRAPH.CENTER,
         italic=True, color=DARK)
    para(doc,
        "donde P(xᵢ) es la probabilidad (frecuencia relativa) del símbolo xᵢ en el mensaje. "
        "El resultado se expresa en bits. Un texto estructurado y repetitivo —como un mensaje "
        "de syslog rutinario— presenta baja entropía, porque unos pocos símbolos concentran "
        "la mayor parte de la probabilidad. En cambio, una carga codificada, cifrada o "
        "aleatoria —típica de inyecciones de comandos, exfiltración codificada o payloads "
        "ofuscados— eleva la entropía al acercar la distribución a la uniformidad. Q-Sentinel "
        "aprovecha esta propiedad como un primer discriminador estadístico barato: mensajes "
        "cuya entropía supera un umbral configurable disparan un análisis más profundo.")

    h2(doc, "2.3 Funciones hash criptográficas: SHA-3-256")
    para(doc,
        "Una función hash criptográfica transforma una entrada de longitud arbitraria en una "
        "salida de longitud fija (el «digest»), de forma que resulte computacionalmente "
        "inviable encontrar dos entradas con el mismo digest (resistencia a colisiones) o "
        "revertir el digest a la entrada (resistencia a la preimagen). SHA-3 (Keccak) es el "
        "estándar más reciente del NIST y, por basarse en una construcción de esponja "
        "distinta a la de SHA-2, aporta diversidad criptográfica. Q-Sentinel sella cada "
        "mensaje de log con SHA-3-256, construyendo una cadena de custodia forense que "
        "permite verificar a posteriori que un registro no fue alterado. El término "
        "«post-cuántico» empleado en la interfaz alude a la mayor resiliencia estructural de "
        "SHA-3 frente a ciertos ataques, no a una garantía formal de seguridad post-cuántica.")

    h2(doc, "2.4 Detección de anomalías y aprendizaje automático")
    h3(doc, "2.4.1 El problema de la detección de anomalías")
    para(doc,
        "Una anomalía es una observación que se desvía significativamente del comportamiento "
        "esperado. En redes, el reto es que «lo esperado» es específico de cada entorno y "
        "cambia con el tiempo. Existen dos grandes familias de enfoques: los supervisados, "
        "que aprenden a partir de ejemplos etiquetados como benignos o maliciosos, y los no "
        "supervisados, que modelan la normalidad y marcan como anómalo lo que se aleja de "
        "ella sin necesidad de etiquetas.")
    h3(doc, "2.4.2 Isolation Forest")
    para(doc,
        "Isolation Forest es un algoritmo no supervisado de detección de anomalías. Su idea "
        "central es que las anomalías son «pocas y diferentes», por lo que resultan más "
        "fáciles de aislar mediante particiones aleatorias del espacio de características. El "
        "algoritmo construye un conjunto de árboles en los que, en cada nodo, se elige una "
        "característica y un valor de corte al azar; las observaciones anómalas quedan "
        "aisladas con menos cortes (menor profundidad promedio), lo que produce una "
        "puntuación de anomalía. Su principal ventaja es que no requiere etiquetas y escala "
        "bien; su limitación es que un ataque cuyos flujos individuales se parecen a tráfico "
        "benigno pequeño no se manifiesta como valor atípico.")
    h3(doc, "2.4.3 Random Forest")
    para(doc,
        "Random Forest es un método supervisado de conjunto que entrena numerosos árboles de "
        "decisión sobre submuestras de los datos y de las características, y promedia sus "
        "votos. Es robusto frente al sobreajuste, maneja bien características heterogéneas y "
        "proporciona una medida de importancia por característica. En este proyecto se emplea "
        "para el modelo heredado porque, al disponer de las etiquetas de CICIDS2017, permite "
        "trazar la frontera entre benigno y ataque que un método no supervisado no logra ver "
        "a nivel de flujo individual.")
    h3(doc, "2.4.4 El conjunto de datos CICIDS2017")
    para(doc,
        "CICIDS2017, elaborado por el Canadian Institute for Cybersecurity de la Universidad "
        "de New Brunswick, es uno de los conjuntos de datos de referencia para la detección "
        "de intrusiones. Contiene aproximadamente 2.8 millones de flujos de red etiquetados, "
        "capturados durante cinco días e incluyendo tráfico benigno y una variedad de ataques "
        "reales: DDoS, escaneo de puertos, fuerza bruta (FTP y SSH), ataques de denegación de "
        "servicio (Hulk, GoldenEye, slowloris, Slowhttptest), botnet, ataques web (fuerza "
        "bruta, inyección SQL, XSS), infiltración y Heartbleed. Cada flujo se describe con "
        "unas 78 características extraídas con la herramienta CICFlowMeter.")

    h2(doc, "2.5 Telemetría de red: NetFlow v9")
    para(doc,
        "NetFlow es un protocolo desarrollado por Cisco para exportar información sobre los "
        "flujos que atraviesan un dispositivo de red. Un «flujo» es una secuencia unidireccional "
        "de paquetes que comparten una quíntupla: IP y puerto de origen, IP y puerto de "
        "destino, y protocolo. La versión 9, definida en el RFC 3954, introduce un formato "
        "basado en plantillas: el exportador envía periódicamente plantillas que describen la "
        "estructura de los registros de datos que enviará a continuación, lo que permite "
        "flexibilidad en los campos exportados. Q-Sentinel implementa un parser propio de "
        "NetFlow v9 —en lugar de depender de librerías externas— para controlar exactamente la "
        "decodificación de los campos que exporta el laboratorio, incluyendo los marcadores "
        "temporales FIRST_SWITCHED y LAST_SWITCHED con los que se calcula la duración del flujo.")

    h2(doc, "2.6 Automatización de infraestructura Cisco vía SSH")
    para(doc,
        "La respuesta autónoma se apoya en la ejecución remota de comandos sobre el router "
        "Cisco mediante SSH, empleando la librería Paramiko. Un aspecto técnico relevante es "
        "que Cisco IOS mantiene el contexto de configuración entre comandos (por ejemplo, tras "
        "entrar en modo de configuración con «configure terminal»). Por ello no basta con "
        "ejecutar comandos aislados: se abre un canal interactivo (invoke_shell) y se envían "
        "las instrucciones en secuencia respetando los tiempos de procesamiento del equipo. "
        "Las contramedidas incluyen el bloqueo de una dirección atacante y el aislamiento de "
        "un segmento completo mediante el apagado administrativo de la subinterfaz "
        "correspondiente.")

    h2(doc, "2.7 Gemelo digital y visualización tridimensional")
    para(doc,
        "Un gemelo digital es una réplica virtual de un sistema físico que refleja su estado "
        "en tiempo real. En Q-Sentinel, el gemelo digital representa la topología de la red "
        "como un organismo tridimensional: una membrana que reacciona al nivel de entropía, "
        "nodos que representan departamentos y equipos, y partículas que representan los flujos "
        "reales de tráfico. La visualización se construye con Three.js (WebGL) e incorpora "
        "técnicas de post-procesado como el bloom para lograr un aspecto luminoso, además de un "
        "shader de ruido simplex que anima la membrana. La comunicación en tiempo real entre el "
        "servidor y el navegador se realiza mediante WebSockets.")


def _cap3_estado_arte(doc):
    h1(doc, "Capítulo 3. Trabajos relacionados y estado del arte")
    para(doc,
        "La detección de intrusiones basada en anomalías es un campo maduro. Los sistemas "
        "comerciales de gestión de eventos e información de seguridad (SIEM) y las plataformas "
        "de orquestación, automatización y respuesta (SOAR) ofrecen correlación de eventos y "
        "automatización de respuestas, pero suelen apoyarse en reglas y requieren una "
        "configuración considerable. En el ámbito académico, numerosos trabajos han evaluado "
        "algoritmos de aprendizaje automático sobre CICIDS2017 y conjuntos similares, "
        "reportando altas tasas de detección con métodos supervisados.")
    para(doc,
        "Q-Sentinel se diferencia en tres aspectos. Primero, articula explícitamente la "
        "complementariedad entre un modelo supervisado con conocimiento heredado y un modelo "
        "no supervisado adaptativo entrenado en línea con el tráfico propio, en lugar de "
        "elegir uno u otro. Segundo, integra la respuesta autónoma sobre la infraestructura "
        "real en el mismo lazo de detección. Tercero, apuesta por una visualización "
        "tridimensional como interfaz principal del operador, frente a los paneles "
        "bidimensionales convencionales. No pretende competir con soluciones industriales, "
        "sino demostrar de forma integral y didáctica un conjunto de ideas.")


def _cap4_arquitectura(doc):
    h1(doc, "Capítulo 4. Arquitectura del sistema")

    h2(doc, "4.1 Visión general")
    para(doc,
        "Q-Sentinel se ejecuta como un único proceso servidor construido sobre FastAPI, que "
        "orquesta varios hilos de captura y expone tanto una API REST como un canal WebSocket. "
        "El frontend es una aplicación web servida por el mismo proceso, que renderiza el "
        "gemelo digital y los paneles del dashboard. El flujo de datos de extremo a extremo "
        "atraviesa las siguientes etapas:")
    code_block(doc,
        "Cisco IOS  ─►  syslog UDP/514        ─┐\n"
        "                                       ├─►  listeners (hilos daemon)\n"
        "Cisco IOS  ─►  NetFlow v9 UDP/2055   ─┘\n"
        "                     │\n"
        "                     ▼\n"
        "        análisis (entropía · detector ML híbrido)\n"
        "                     │\n"
        "                     ▼\n"
        "        persistencia SQLite (WAL)  +  respuesta SSH autónoma\n"
        "                     │\n"
        "                     ▼\n"
        "        broadcast WebSocket  ─►  gemelo digital 3D (Three.js)")

    h2(doc, "4.2 Componentes")
    table(doc,
        ["Módulo", "Responsabilidad"],
        [
            ["core/config.py", "Constantes del laboratorio, umbrales y credenciales por variable de entorno"],
            ["core/analysis.py", "Entropía de Shannon, hash SHA-3-256, correlación de IP atacante"],
            ["core/responder.py", "Respuesta autónoma vía SSH (Paramiko) sobre Cisco IOS"],
            ["core/events.py", "Modelo de datos del evento (SentinelEvent)"],
            ["core/flowlistener.py", "Parser propio de NetFlow v9 (RFC 3954)"],
            ["core/storage.py", "Persistencia SQLite en modo WAL"],
            ["core/topology.py", "Modelo lógico de la red desde topology.yaml"],
            ["ml/features.py", "Vector de características compartido por toda la capa ML"],
            ["ml/prepare_cicids.py", "Extracción de características de CICIDS2017"],
            ["ml/train.py", "Entrenamiento del modelo heredado (Random Forest)"],
            ["ml/local.py", "Modelo local adaptativo (Isolation Forest)"],
            ["ml/detector.py", "Detector híbrido y orquestación de la inferencia"],
            ["server.py", "FastAPI: WebSocket, API REST, hilos de captura"],
            ["web/", "Gemelo digital 3D, dashboard y gráficas"],
        ])

    h2(doc, "4.3 Fases de desarrollo")
    table(doc,
        ["Fase", "Entregable", "Estado"],
        [
            ["A–E", "Núcleo modular: entropía, SHA-3, respuesta SSH autónoma", "Completado"],
            ["F", "Servidor FastAPI + WebSocket con envelope {kind, payload}", "Completado"],
            ["G", "Gemelo digital 3D con Three.js", "Completado"],
            ["H", "Aislamiento de segmentos táctil (touch-to-isolate)", "Completado"],
            ["I", "Ingesta NetFlow v9 + persistencia SQLite + gráfica de entropía", "Completado"],
            ["J", "Detector ML híbrido adaptativo (CICIDS + línea base local)", "Completado"],
            ["K", "Inspección profunda de paquetes (DPI)", "Trabajo futuro"],
        ])

    h2(doc, "4.4 El laboratorio de pruebas")
    para(doc,
        "La topología de referencia se define declarativamente en un archivo YAML y modela "
        "una red corporativa con 17 nodos y 16 enlaces. El núcleo de gestión aloja el propio "
        "Q-Sentinel y un router Cisco 7200; un switch de capa 2 troncaliza seis "
        "departamentos, cada uno en su propia VLAN y subred; y una zona externa no confiable "
        "aloja al atacante. La tabla siguiente resume la segmentación.")
    table(doc,
        ["Departamento", "Subred", "VLAN", "Interfaz Cisco", "Criticidad"],
        [
            ["Finanzas", "10.10.10.0/24", "10", "f1/0.10", "Alta"],
            ["RR.HH.", "10.10.20.0/24", "20", "f1/0.20", "Alta"],
            ["TI", "10.10.30.0/24", "30", "f1/0.30", "Crítica"],
            ["I+D", "10.10.40.0/24", "40", "f1/0.40", "Crítica"],
            ["Producción", "10.10.50.0/24", "50", "f1/0.50", "Media"],
            ["Ventas", "10.10.60.0/24", "60", "f1/0.60", "Media"],
            ["Zona externa", "10.0.0.0/24", "—", "f2/0", "No confiable"],
        ])


def _cap5_implementacion(doc):
    h1(doc, "Capítulo 5. Diseño e implementación")

    h2(doc, "5.1 El motor de análisis estadístico")
    para(doc,
        "El módulo de análisis implementa la entropía de Shannon sobre los caracteres de cada "
        "mensaje de syslog y su sellado con SHA-3-256. Un mensaje se considera de confianza si "
        "contiene alguna de las palabras clave de una lista blanca heurística (por ejemplo, "
        "eventos rutinarios de TFTP, reinicios programados o sesiones SSH legítimas). El "
        "sistema marca como anómalo un evento cuando su entropía supera el umbral configurado "
        "(5.0 bits por defecto) y no pertenece a la lista de confianza.")
    code_block(doc,
        "def calcular_entropia(texto: str) -> float:\n"
        "    # H(X) = -sum P(xi) log2 P(xi) sobre los caracteres del mensaje\n"
        "    longitud = len(texto)\n"
        "    return -sum((f/longitud) * math.log2(f/longitud)\n"
        "                for f in Counter(texto).values())")
    para(doc,
        "Cuando se detecta una anomalía, el sistema intenta correlacionar la dirección del "
        "atacante mediante dos estrategias: el Plan A extrae la primera dirección IP presente "
        "en el mensaje que no corresponda al router de administración ni al loopback; el Plan B "
        "se activa cuando el origen se reporta como desconocido y recurre a la subred de "
        "ataque conocida del laboratorio.")

    h2(doc, "5.2 La respuesta autónoma")
    para(doc,
        "Ante una amenaza correlacionada, el respondedor abre una sesión SSH con el router y "
        "ejecuta la secuencia de comandos de contención. Se utiliza un canal interactivo para "
        "preservar el contexto de configuración de Cisco IOS entre comandos. El sistema "
        "distingue dos acciones: el bloqueo de una dirección concreta y el aislamiento de un "
        "segmento completo mediante el apagado administrativo de la subinterfaz. Cada acción "
        "se registra íntegramente —incluso los intentos fallidos— para auditoría posterior.")

    h2(doc, "5.3 El parser NetFlow v9")
    para(doc,
        "El listener de NetFlow escucha en el puerto UDP 2055 en un hilo dedicado. El parser "
        "decodifica la cabecera de la versión 9, procesa las plantillas y las almacena "
        "indexadas por exportador y por identificador, y a continuación decodifica los "
        "registros de datos según la plantilla correspondiente. Un aspecto crítico de la "
        "implementación es la deduplicación: cuando Cisco IOS exporta el mismo flujo tanto en "
        "ingreso como en egreso, se reciben duplicados que se filtran mediante una ventana "
        "temporal sobre la quíntupla del flujo. A partir de los marcadores FIRST_SWITCHED y "
        "LAST_SWITCHED se calcula la duración del flujo, corrigiendo el desbordamiento del "
        "contador de 32 bits del tiempo de actividad del router.")

    h2(doc, "5.4 La capa de persistencia")
    para(doc,
        "La persistencia se apoya en SQLite configurado en modo WAL (Write-Ahead Logging), que "
        "permite que lecturas y escrituras concurrentes no se bloqueen entre sí. Un cerrojo "
        "serializa las escrituras provenientes de los hilos de captura y de los manejadores de "
        "la API. Se mantienen tres tablas principales: eventos, flujos y registro de "
        "aislamientos. La tabla de flujos se amplió con una columna de duración mediante una "
        "migración aditiva idempotente, de forma que las bases de datos creadas con esquemas "
        "anteriores se actualizan automáticamente al arrancar.")

    h2(doc, "5.5 El servidor y la comunicación en tiempo real")
    para(doc,
        "El servidor FastAPI expone endpoints REST para consultar el histórico de eventos, "
        "flujos, series temporales de entropía, estado del modelo de aprendizaje automático y "
        "acciones de aislamiento, además del canal WebSocket que difunde en tiempo real los "
        "eventos, los cambios de estado de la topología y los flujos. Los mensajes siguen un "
        "sobre uniforme con los campos «kind» y «payload». Un gestor de conexiones mantiene el "
        "conjunto de clientes activos, un historial para hidratar a los clientes que se "
        "conectan tarde, y los contadores agregados que se restauran desde la base de datos "
        "tras un reinicio.")


def _cap6_detector_ml(doc):
    h1(doc, "Capítulo 6. El detector de aprendizaje automático híbrido")

    h2(doc, "6.1 Motivación: las limitaciones del umbral fijo")
    para(doc,
        "El detector estadístico original marca una anomalía cuando la entropía supera un "
        "umbral fijo. Este criterio, aunque útil, es rígido: no conoce la red que protege ni "
        "evoluciona con ella. La Fase J sustituye este umbral por un detector que aprende, "
        "materializando por fin la parte «adaptativa» del nombre del proyecto.")

    h2(doc, "6.2 El vector de características compartido")
    para(doc,
        "Toda la capa de aprendizaje automático opera sobre un vector común de siete "
        "características derivadas de cada flujo. La coherencia es crítica: ese vector se "
        "construye desde tres orígenes distintos —los CSV de CICIDS2017 durante el "
        "entrenamiento heredado, la tabla de flujos durante el entrenamiento local y los "
        "flujos en vivo durante la inferencia— y cualquier divergencia en las fórmulas "
        "introduciría errores silenciosos. Por ello se centralizó en un único módulo.")
    table(doc,
        ["#", "Característica", "Descripción"],
        [
            ["1", "dst_port", "Puerto destino (la más discriminante)"],
            ["2", "duration_ms", "Duración del flujo (LAST_SWITCHED − FIRST_SWITCHED)"],
            ["3", "packets", "Número total de paquetes del flujo"],
            ["4", "bytes", "Número total de bytes del flujo"],
            ["5", "bytes_per_packet", "Tamaño medio de paquete"],
            ["6", "packets_per_s", "Tasa de paquetes (firma de floods/DoS)"],
            ["7", "bytes_per_s", "Tasa de bytes (firma de exfiltración)"],
        ])

    h2(doc, "6.3 El modelo heredado (supervisado)")
    para(doc,
        "El modelo heredado se entrena con CICIDS2017. Durante el desarrollo se produjo un "
        "hallazgo determinante: un Isolation Forest no supervisado, entrenado sólo con tráfico "
        "benigno, detectaba menos del 1 % de los ataques. La razón es que un flujo individual "
        "de escaneo de puertos o de denegación de servicio no es un valor atípico: se parece a "
        "un flujo benigno pequeño. La frontera entre ataque y tráfico normal existe en el "
        "espacio de características, pero sólo las etiquetas la revelan. Por ello el modelo "
        "heredado se implementó como un clasificador supervisado Random Forest, que aprovecha "
        "las etiquetas de CICIDS2017.")
    para(doc, "Resultados de validación sobre un 25 % de datos nunca vistos:", bold=True, after=2)
    table(doc,
        ["Métrica", "Valor"],
        [
            ["Detección global de ataques", "98.03 %"],
            ["Tasa de falsos positivos", "0.96 %"],
            ["DDoS", "99.72 %"],
            ["Escaneo de puertos (PortScan)", "99.68 %"],
            ["DoS Hulk / GoldenEye / slowloris", "> 98 %"],
            ["Fuerza bruta FTP / SSH", "> 99 %"],
            ["Heartbleed", "100 %"],
            ["Ataques web / Infiltración (a nivel de flujo)", "40 – 67 %"],
        ])
    para(doc,
        "La importancia de características confirma la intuición del dominio: el puerto destino "
        "es la variable más discriminante (0.281), seguida del tamaño medio de paquete y del "
        "volumen de bytes. Los ataques a nivel de contenido (inyección SQL, XSS) presentan "
        "tasas menores porque su firma vive en la carga HTTP, invisible a nivel de flujo.")

    h2(doc, "6.4 El modelo local adaptativo (no supervisado)")
    para(doc,
        "El modelo local es la mitad adaptativa del sistema. Se trata de un Isolation Forest "
        "entrenado exclusivamente con el tráfico de la propia red, tomado de la tabla de "
        "flujos con una ventana móvil de siete días, y re-entrenado periódicamente. No conoce "
        "ninguna firma de ataque: marca como anómalo lo que se desvía de la línea base local, "
        "cubriendo así amenazas que CICIDS2017 nunca vio. Cuando la ventana contiene menos de "
        "200 flujos, el modelo se declara «no listo» y se abstiene de opinar, bajo el "
        "principio de que es preferible carecer de juicio a emitir uno sin base estadística. "
        "El modelo opera en un espacio logarítmico de las magnitudes, dado que los cortes del "
        "Isolation Forest son sensibles a la escala y variables como los bytes o la duración "
        "abarcan varios órdenes de magnitud.")

    h2(doc, "6.5 El veredicto híbrido")
    para(doc,
        "Cada flujo en vivo se evalúa con ambos modelos. El veredicto final es la unión lógica "
        "de ambos: un flujo se marca como anómalo si cualquiera de los dos lo señala, e incluye "
        "la atribución de qué detector lo marcó y con qué confianza, de modo que la interfaz "
        "pueda explicar el porqué de cada alerta en lugar de ofrecer un veredicto opaco. El "
        "sistema degrada con elegancia: si falta el modelo heredado, opina sólo el local; si el "
        "modelo local aún no tiene línea base, opina sólo el heredado. Un trabajo asíncrono "
        "re-entrena la línea base local al arranque del servidor y de forma periódica, sin "
        "bloquear el bucle de eventos.")


def _cap7_digital_twin(doc):
    h1(doc, "Capítulo 7. El gemelo digital tridimensional")

    h2(doc, "7.1 Concepto visual")
    para(doc,
        "El gemelo digital representa la red como un organismo vivo encerrado en una membrana "
        "esférica translúcida. Los departamentos y equipos son nodos luminosos —las "
        "«neuronas»— y la infraestructura de red conserva formas cristalinas que permiten "
        "distinguir su tipo de un vistazo. Los flujos de red reales viajan como partículas a "
        "lo largo de rutas que respetan la lógica de conmutación de la red (los flujos entre "
        "departamentos pasan por el switch; los que van hacia el exterior, por el router).")

    h2(doc, "7.2 Técnicas de renderizado")
    para(doc,
        "La membrana se construye con una geometría de icosaedro de alta subdivisión y un "
        "shader que aplica ruido simplex tridimensional para animar su superficie. La "
        "intensidad del desplazamiento y el color de la membrana responden al nivel de "
        "entropía suavizado: en calma se muestra oscura y cian; al elevarse la entropía, se "
        "tiñe de ámbar y rojo. Para lograr un aspecto luminoso moderno se emplea "
        "post-procesado con un paso de bloom, calibrado con un umbral alto para que sólo los "
        "elementos verdaderamente brillantes florezcan, evitando la saturación de la imagen.")
    para(doc,
        "Un principio de diseño rector es la honestidad visual: todo lo que se mueve en la "
        "escena debe representar tráfico real. Por ello se descartó cualquier animación "
        "ambiental decorativa que pudiera inducir al operador a pensar que hay actividad "
        "cuando la red está en silencio. Asimismo, el desplazamiento de la membrana se acota "
        "de forma asimétrica —puede abultarse hacia afuera pero apenas hundirse hacia "
        "adentro— para garantizar que ningún nodo del perímetro quede fuera de la malla por "
        "muy elevada que sea la entropía.")

    h2(doc, "7.3 Interacción: aislamiento táctil")
    para(doc,
        "El operador puede hacer clic sobre un departamento o sobre la zona externa para abrir "
        "un cuadro de diálogo que permite aislar ese segmento. La acción se traduce en la "
        "ejecución remota de los comandos de apagado y reactivación de la subinterfaz "
        "correspondiente en el router, y el cambio se persiste. El estado de aislamiento se "
        "sincroniza en tiempo real con todos los clientes conectados mediante WebSocket, y se "
        "refleja visualmente con un tinte gris y un halo rojo pulsante sobre el nodo afectado.")

    h2(doc, "7.4 El dashboard")
    para(doc,
        "La interfaz se organiza en bandas jerárquicas siguiendo criterios de un SOC "
        "profesional. Una banda superior de indicadores agrupa las métricas por función: "
        "detección (eventos y anomalías), respuesta autónoma (direcciones bloqueadas) y señal "
        "en vivo (entropía y estado del detector de aprendizaje automático). El panel lateral "
        "ordena la información por urgencia operativa: primero las amenazas neutralizadas, "
        "después la consola de respuesta SSH y por último la cadena forense de hashes. Al pie, "
        "una banda temporal reúne la gráfica de entropía de los últimos treinta minutos y un "
        "ticker de eventos.")


def _cap8_validacion(doc):
    h1(doc, "Capítulo 8. Validación y resultados")

    h2(doc, "8.1 Metodología de validación")
    para(doc,
        "Para validar el detector sin depender de un volumen elevado de tráfico de "
        "laboratorio, se desarrollaron simuladores que inyectan datagramas NetFlow v9 reales "
        "en el colector, ejerciendo el pipeline completo del sistema: parser, deduplicación, "
        "extracción de características, detector y visualización. A diferencia de un inyector "
        "de eventos sintéticos que forzara el veredicto, este enfoque hace que el detector "
        "decida de verdad. Un aspecto metodológico importante es que los valores de cada "
        "escenario de ataque se calibraron con las distribuciones estadísticas reales medidas "
        "sobre el propio CICIDS2017, para que las firmas fueran representativas.")

    h2(doc, "8.2 El hallazgo de la calibración")
    para(doc,
        "El primer intento de simular un escaneo de puertos no fue detectado por el modelo "
        "heredado. El análisis reveló que los flujos de escaneo reales de CICIDS2017 presentan "
        "una firma muy particular —dos paquetes y apenas seis bytes, es decir, sondas "
        "prácticamente vacías con puertos destino repartidos por todo el rango— que los "
        "valores inventados inicialmente no reproducían. Tras recalibrar los generadores con "
        "las distribuciones reales, la detección se restableció. Este episodio ilustra una "
        "lección de fondo: la detección a nivel de flujo individual tiene un techo, y un "
        "escaneo se reconoce mejor como patrón agregado que flujo a flujo.")

    h2(doc, "8.3 Resultados del ataque multi-etapa")
    para(doc,
        "Se ejecutó un ataque multi-etapa contra el departamento crítico de TI, compuesto por "
        "reconocimiento, denegación de servicio distribuida, fuerza bruta y exfiltración. Los "
        "resultados fueron los siguientes.")
    table(doc,
        ["Etapa", "Flujos", "Detección"],
        [
            ["Reconocimiento (escaneo de puertos)", "60", "≈ 67 %"],
            ["DDoS (botnet externa hacia el puerto 80)", "80", "≈ 88 %"],
            ["Fuerza bruta SSH (puerto 22)", "50", "≈ 78 %"],
            ["Exfiltración (50 MB al exterior)", "6", "capturada por el modelo local"],
        ])
    para(doc,
        "En conjunto, de 218 flujos evaluados el detector marcó 141 como anómalos, sin ningún "
        "error de parseo. Las detecciones no alcanzan el 100 % porque, a nivel de flujo "
        "individual, siempre existe ambigüedad; sin embargo, la cobertura es sólida y, sobre "
        "todo, honesta.")

    h2(doc, "8.4 La demostración del comportamiento adaptativo")
    para(doc,
        "La prueba más significativa consistió en verificar que el sistema aprende. Tras "
        "construir la línea base local con 300 flujos de tráfico normal y re-entrenar el "
        "modelo local, se relanzó la exfiltración y se desglosó el veredicto por detector. El "
        "resultado fue concluyente: dos de cada ocho exfiltraciones fueron marcadas "
        "ÚNICAMENTE por el modelo local, porque ese patrón —una transferencia masiva hacia un "
        "puerto inusual— no existe en CICIDS2017 y, por tanto, el modelo heredado no lo "
        "reconocía. La inmunidad adquirida cubriendo exactamente lo que la heredada desconoce: "
        "la tesis central del proyecto, demostrada empíricamente.")
    para(doc,
        "Un experimento complementario mostró el fenómeno inverso y su riesgo asociado: cuando "
        "la línea base se entrena incluyendo el tráfico de ataque, la detección de la "
        "exfiltración cae (de 20 sobre 20 a 11 sobre 20). Esto documenta la vulnerabilidad de "
        "envenenamiento de la línea base, que se discute en el capítulo siguiente.")


def _cap9_limitaciones(doc):
    h1(doc, "Capítulo 9. Limitaciones conocidas y trabajo futuro")

    h2(doc, "9.1 Limitaciones")
    bullet(doc, "un ataque distribuido en el tiempo se "
        "reconoce mejor como patrón agregado que flujo a flujo; la detección por flujo "
        "individual tiene un techo intrínseco.", bold_prefix="Detección por flujo — ")
    bullet(doc, "un atacante paciente que genere tráfico "
        "malicioso sostenido podría lograr que el modelo local lo asimile como normal. Se "
        "cuantificó experimentalmente esta degradación.", bold_prefix="Envenenamiento — ")
    bullet(doc, "los ataques a nivel de contenido (inyección SQL, "
        "XSS) son en gran medida invisibles a nivel de flujo y requerirían inspección profunda "
        "de paquetes.", bold_prefix="Contenido de aplicación — ")
    bullet(doc, "el sistema se validó sobre tráfico IPv4 y sobre la "
        "variante de NetFlow v9 de Cisco IOS; otros entornos requerirían adaptación.",
        bold_prefix="Alcance de protocolo — ")

    h2(doc, "9.2 Trabajo futuro")
    numbered(doc, "Inspección profunda de paquetes (Fase K) con Scapy, para cubrir los ataques "
        "a nivel de contenido de aplicación.")
    numbered(doc, "Adaptador de respuesta genérico (patrón SOAR) que generalice las "
        "contramedidas más allá de Cisco IOS, hacia fabricantes como Fortinet o Palo Alto.")
    numbered(doc, "Contenerización del sistema completo con Docker y docker-compose para "
        "simplificar el despliegue.")
    numbered(doc, "Mecanismos de mitigación del envenenamiento de la línea base, como el "
        "filtrado del tráfico ya marcado como anómalo antes del re-entrenamiento.")
    numbered(doc, "Correlación temporal de flujos para detectar patrones agregados (por "
        "ejemplo, un escaneo completo) además de flujos individuales.")


def _cap10_conclusiones(doc):
    h1(doc, "Capítulo 10. Conclusiones")
    para(doc,
        "Q-Sentinel cumple el objetivo general planteado: constituye una plataforma integral "
        "que detecta anomalías combinando análisis estadístico y aprendizaje automático "
        "adaptativo, responde de forma autónoma sobre infraestructura Cisco y representa el "
        "estado de la red en un gemelo digital tridimensional. Cada uno de los objetivos "
        "específicos se materializó en un componente verificable y se validó de forma aislada "
        "e integrada.")
    para(doc,
        "El aporte más valioso del trabajo es haber demostrado empíricamente la "
        "complementariedad de los dos modelos del detector híbrido. La evidencia de que el "
        "modelo local captura exfiltraciones que el modelo heredado ignora confirma que la "
        "arquitectura de doble inmunidad no es sólo una metáfora atractiva, sino una decisión "
        "de diseño con consecuencias medibles. Igualmente valioso es el rigor con que se "
        "documentaron las limitaciones: reconocer el techo de la detección por flujo y el "
        "riesgo de envenenamiento de la línea base aporta honestidad técnica al proyecto.")
    para(doc,
        "En el plano formativo, el desarrollo integró de forma coherente teoría de la "
        "información, criptografía, automatización de redes, aprendizaje automático y "
        "visualización tridimensional, ofreciendo una visión de extremo a extremo de lo que "
        "implica construir un sistema de defensa. El resultado es una base sólida sobre la "
        "que se pueden edificar las extensiones planteadas como trabajo futuro.")


def _referencias(doc):
    h1(doc, "Referencias")
    refs = [
        "Shannon, C. E. (1948). A Mathematical Theory of Communication. Bell System "
        "Technical Journal, 27(3), 379–423.",
        "National Institute of Standards and Technology (2015). FIPS PUB 202: SHA-3 "
        "Standard: Permutation-Based Hash and Extendable-Output Functions.",
        "Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation Forest. IEEE "
        "International Conference on Data Mining (ICDM), 413–422.",
        "Breiman, L. (2001). Random Forests. Machine Learning, 45(1), 5–32.",
        "Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward Generating a "
        "New Intrusion Detection Dataset and Intrusion Traffic Characterization (CICIDS2017). "
        "ICISSP, 108–116.",
        "Claise, B. (Ed.) (2004). RFC 3954: Cisco Systems NetFlow Services Export Version 9. "
        "Internet Engineering Task Force.",
        "Pedregosa, F. et al. (2011). Scikit-learn: Machine Learning in Python. Journal of "
        "Machine Learning Research, 12, 2825–2830.",
        "Ramírez, S. (2018). FastAPI Documentation. https://fastapi.tiangolo.com",
        "Cabello, R. (mrdoob) et al. Three.js Documentation. https://threejs.org",
        "Paramiko Project. Paramiko: Python implementation of SSHv2. https://www.paramiko.org",
    ]
    for i, r in enumerate(refs, 1):
        p = doc.add_paragraph()
        p.add_run(f"[{i}] ").bold = True
        p.add_run(r)
        p.paragraph_format.space_after = Pt(6)


def _anexos(doc):
    h1(doc, "Anexos")

    h2(doc, "Anexo A. Estructura del proyecto")
    code_block(doc,
        "Sentinel/\n"
        "├── core/            # motor: análisis, respuesta, storage, topología\n"
        "│   ├── analysis.py       entropía de Shannon + SHA-3 + correlación\n"
        "│   ├── responder.py      respuesta SSH autónoma (Paramiko)\n"
        "│   ├── flowlistener.py   parser NetFlow v9 (RFC 3954)\n"
        "│   ├── storage.py        persistencia SQLite (WAL)\n"
        "│   ├── topology.py       modelo lógico de la red\n"
        "│   └── config.py         umbrales y credenciales\n"
        "├── ml/              # detector híbrido\n"
        "│   ├── features.py       vector de 7 características compartido\n"
        "│   ├── prepare_cicids.py extracción de CICIDS2017\n"
        "│   ├── train.py          entrenamiento del modelo heredado\n"
        "│   ├── local.py          modelo local adaptativo\n"
        "│   └── detector.py       veredicto híbrido\n"
        "├── web/             # gemelo digital + dashboard\n"
        "├── scripts/         # simuladores de validación y generadores de docs\n"
        "├── server.py        # FastAPI + WebSocket\n"
        "└── topology.yaml    # definición de la topología del laboratorio")

    h2(doc, "Anexo B. Puesta en marcha")
    para(doc, "Preparación del modelo heredado (una sola vez):", bold=True, after=2)
    code_block(doc,
        "python -m ml.prepare_cicids    # extrae características de CICIDS2017\n"
        "python -m ml.train             # entrena el Random Forest")
    para(doc, "Arranque del servidor:", bold=True, after=2)
    code_block(doc,
        "python server.py               # interfaz en http://localhost:8000")
    para(doc, "Validación del detector (con el servidor en ejecución):", bold=True, after=2)
    code_block(doc,
        "python -m scripts.traffic_sim --flows 300    # tráfico normal (línea base)\n"
        "python -m scripts.attack_sim --attack all     # ataque multi-etapa\n"
        "python -m scripts.demo_breakdown              # desglose por detector")

    h2(doc, "Anexo C. Pila tecnológica")
    table(doc,
        ["Capa", "Tecnologías"],
        [
            ["Lenguaje", "Python 3.13, JavaScript (ES Modules)"],
            ["Backend", "FastAPI, Uvicorn, WebSockets, asyncio + threading"],
            ["Aprendizaje automático", "scikit-learn, pandas, NumPy, joblib"],
            ["Red", "Paramiko (SSH), NetFlow v9 (parser propio), syslog"],
            ["Persistencia", "SQLite (modo WAL)"],
            ["Frontend", "Three.js (WebGL), CSS2DRenderer, EffectComposer (bloom)"],
            ["Laboratorio", "EVE-NG, Cisco IOS 7200, IOSvL2, VPCS"],
        ])

    h2(doc, "Anexo D. Parámetros de configuración relevantes")
    table(doc,
        ["Parámetro", "Valor", "Descripción"],
        [
            ["UMBRAL_ENTROPIA", "5.0 bits", "Umbral estadístico de anomalía"],
            ["Modelo heredado", "Random Forest, 150 árboles", "class_weight balanceado"],
            ["Modelo local", "Isolation Forest, 150 árboles", "contamination 0.02"],
            ["Ventana de entrenamiento local", "7 días", "ventana móvil de flujos"],
            ["Flujos mínimos (línea base)", "200", "por debajo, el modelo se abstiene"],
            ["Re-entrenamiento local", "cada 6 horas", "más al arranque del servidor"],
            ["Puerto syslog", "UDP/514", "ingesta de eventos"],
            ["Puerto NetFlow", "UDP/2055", "ingesta de flujos"],
        ])


if __name__ == "__main__":
    build()
