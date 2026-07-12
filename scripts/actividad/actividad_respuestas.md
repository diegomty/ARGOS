# Análisis y priorización de incidentes de seguridad de datos

**Alumno:** Juan Diego
**Fecha:** 2026-05-15
**Entorno:** Q-Sentinel — Sistema de Inmunidad Digital Adaptativa
- Lab simulado en EVE-NG (R1 Cisco 7200, SW1, hosts internos en VLANs 10-60, atacante externo en 10.0.0.0/24)
- Detección: entropía de Shannon sobre cada datagrama syslog, umbral H > 5.0 bits
- Cadena de custodia: hash SHA-3-256 por mensaje
- Persistencia: SQLite WAL (`qsentinel.db`)
- Respuesta autónoma: ACL `BLACKLIST` aplicada vía SSH a R1

---

## 1. Análisis de logs y eventos

### Dataset analizado

Se inyectaron **25 registros syslog** al listener UDP/514 de Q-Sentinel:
- **14 eventos normales** entre 08:55 y 17:00, con IPs internas (`192.168.1.10`, `192.168.1.15`, `192.168.1.22`, `192.168.1.30`) y usuarios reales (admin, analista, rrhh, finanzas).
- **11 eventos sospechosos** entre 02:55 y 03:45, con IP externa única `185.32.44.10` y escalamiento `admin → root`.

Cada inyección quedó persistida en SQLite con timestamp, hash SHA-3 y valor de entropía.

### Pregunta 1 — Eventos sospechosos, anomalías y comportamientos fuera de patrón

**Detectados automáticamente por Sentinel (H > 5.0 bits):**

| # | Hora | Usuario | Evento | IP | H (bits) |
|---|------|---------|--------|-----|----------|
| 1 | 02:55 | admin | login | 185.32.44.10 | 5.06 |
| 2 | 02:57 | admin | descarga base completa | 185.32.44.10 | 5.05 |
| 3 | 03:01 | admin | logout | 185.32.44.10 | 5.03 |
| 4 | 03:10 | root | intento fallido login | 185.32.44.10 | 5.06 |
| 5 | 03:12 | root | intento fallido login | 185.32.44.10 | 5.05 |
| 6 | 03:15 | root | intento fallido login | 185.32.44.10 | 5.07 |
| 7 | 03:17 | root | intento fallido login | 185.32.44.10 | 5.04 |
| 8 | 03:22 | root | exfiltración datos clientes | 185.32.44.10 | 5.02 |
| 9 | 03:30 | root | modificación logs sistema | 185.32.44.10 | 5.07 |
| 10 | 03:45 | root | creación usuario backdoor | 185.32.44.10 | 5.04 |

**Comportamientos fuera de patrón identificados:**

1. **Horario anómalo:** toda la actividad sospechosa ocurre entre las **02:55 y 03:45**, fuera del horario laboral. La línea base de usuarios reales se concentra entre 08:55 y 17:00.
2. **IP externa única:** `185.32.44.10` no pertenece al rango interno `192.168.1.0/24`. Es un origen externo no autorizado.
3. **Escalamiento de privilegios:** la sesión inicia con `admin` (02:55-03:01), después aparece la cuenta `root` con **4 intentos fallidos consecutivos** (03:10, 03:12, 03:15, 03:17) seguidos de un **login exitoso a las 03:20**. Patrón clásico de fuerza bruta seguida de compromiso.
4. **Cadena de impacto post-acceso:** tras el login de `root` se observa exfiltración (03:22), manipulación de logs (03:30) y persistencia mediante backdoor (03:45).

**Punto ciego del detector estadístico (importante):**

El evento `03:20 root login exitoso` **NO fue marcado como anomalía** (H quedó bajo el umbral de 5.0). Este es justamente el evento bisagra del ataque — el momento del compromiso real. La razón es que el mensaje es corto y poco diverso a nivel de caracteres, por lo que su entropía de Shannon queda por debajo del umbral. Esta limitación demuestra que la detección estadística necesita complementarse con reglas semánticas (ej. "todo login exitoso de `root` desde IP externa requiere alerta independientemente de H") y con supervisión humana.

### Pregunta 2 — Principios de seguridad afectados

| Principio | Cómo se vulnera | Evidencia en los logs |
|-----------|-----------------|------------------------|
| **Confidencialidad** | Descarga masiva y exfiltración de datos por una identidad no autorizada | `02:57 admin descarga base completa` y `03:22 root exfiltración datos clientes` |
| **Integridad** | Manipulación posterior de los logs del sistema y creación de usuarios no documentados | `03:30 root modificación logs sistema` y `03:45 root creación usuario backdoor` |
| **Disponibilidad** | El escalamiento a `root` deja al atacante con capacidad de alterar/borrar servicios; el backdoor implica persistencia indefinida que compromete la operación futura | `03:45 root creación usuario backdoor` |

Los tres pilares del triángulo CIA se ven afectados en este incidente. La **confidencialidad** es la primera comprometida temporalmente (a las 02:57), seguida por **integridad** y **disponibilidad** una vez que el atacante obtiene `root`.

### Pregunta 3 — Evento más crítico y por qué

**Evento más crítico: `03:20 root login exitoso` desde `185.32.44.10`.**

Razones, en orden de importancia:

1. **Es el punto de compromiso real.** Hasta ese momento solo había intentos (señales). Desde ese segundo en adelante el atacante tiene control con privilegios máximos.
2. **Habilita todo el resto.** Cada evento posterior (exfiltración, manipulación de logs, backdoor) es **consecuencia directa** de este login. Sin él, los siguientes no existen.
3. **Pasó desapercibido para el detector automático** (H < 5.0). Un atacante real podría haber detenido el ataque aquí y mantener acceso latente sin generar alerta estadística. Lo crítico no es solo lo que pasó, sino que el sistema no lo vio.
4. **Combina los tres factores de riesgo simultáneamente:** identidad privilegiada (`root`) + origen externo (`185.32.44.10`) + horario anómalo (03:20 AM) + contexto previo (precedido de brute force).

Si solo se pudiera responder a un único evento de toda la traza, sería este: porque cortar la sesión en `03:20` (terminar el SSH, invalidar credenciales, bloquear la IP) habría detenido todo lo que viene después.

---

*Documento generado a partir de evidencia real extraída del SQLite de Q-Sentinel (endpoint `/api/history?anomaly_only=true`). Las capturas del dashboard y el dump del JSON están disponibles bajo demanda.*

---

## 2. Vulnerabilidades detectadas

Se levantaron **15 hallazgos** combinando los 6 del enunciado del PDF y 9 hallazgos adicionales observados en el lab Q-Sentinel (EVE-NG + Cisco 7200 + FastAPI + SQLite).

### Pregunta 4 — Clasificación: vulnerabilidad / amenaza / riesgo

| # | Hallazgo | Tipo | Justificación |
|---|----------|------|---------------|
| 1 | Contraseña débil en usuario `admin` (`admin/root` por defecto en el lab) | Vulnerabilidad | Debilidad inherente a la configuración: credenciales predecibles y reutilizadas. |
| 2 | Puerto 22 (SSH) del router R1 alcanzable desde la subred externa `10.0.0.0/24` | Vulnerabilidad | Exposición innecesaria de un servicio de gestión a una zona no confiable. |
| 3 | Certificado digital del frontend expirado | Vulnerabilidad | El navegador deja de validar la identidad del servidor y se rompe la confianza TLS. |
| 4 | Base de datos `qsentinel.db` (SQLite) sin cifrado en reposo | Vulnerabilidad | Cualquier acceso al disco lee logs, hashes y eventos en claro. |
| 5 | Ausencia de MFA en accesos administrativos (router y dashboard) | Vulnerabilidad | El control de acceso depende exclusivamente de la contraseña. |
| 6 | Logs sin monitoreo humano automático fuera del horario laboral | Vulnerabilidad | Sentinel detecta, pero no hay analista de guardia 24/7 que valide. |
| 7 | Syslog transmitido por UDP/514 en texto plano | Vulnerabilidad | Sin TLS/DTLS: los logs pueden interceptarse o suplantarse en tránsito. |
| 8 | Endpoints API (`/api/history`, `/api/isolate`, WebSocket) sin autenticación | Vulnerabilidad | Cualquiera con acceso a la red de gestión puede consultar evidencia o disparar acciones. |
| 9 | Umbral de entropía fijo (H > 5.0) sin ajuste adaptativo | Vulnerabilidad | Un atacante puede mantener mensajes "estadísticamente normales" para evadir la detección (ver evento 03:20 del bloque 1). |
| 10 | Red plana: la subred atacante `10.0.0.0/24` tiene ruta directa hasta R1 | Vulnerabilidad | Falta de segmentación / jump host entre zonas. |
| 11 | IP externa `185.32.44.10` ejecutando fuerza bruta contra `root` | Amenaza | Agente externo activo intentando explotar credenciales. |
| 12 | Exfiltración de la base de clientes (`03:22`) | Amenaza | Evento observado de pérdida de confidencialidad en curso. |
| 13 | Manipulación de los logs del sistema (`03:30`) | Amenaza | Acción dirigida contra la integridad de la evidencia forense. |
| 14 | Creación de un usuario backdoor (`03:45`) | Amenaza | Acción dirigida a establecer persistencia post-compromiso. |
| 15 | Compromiso silencioso por evento bajo umbral (caso `03:20 root login exitoso`) | Riesgo | Combinación V9 + A11 → resultado: el sistema no alerta del momento bisagra del ataque. |

> **Nota:** la mayoría de los hallazgos son vulnerabilidades (debilidades intrínsecas). Los hallazgos 11-14 son **amenazas observadas en logs reales** del incidente, no hipotéticas. El hallazgo 15 es el **riesgo materializado** durante la inyección — se demostró empíricamente que existe.

### Pregunta 5 — Matriz de riesgo

Escalas usadas: Impacto = {Bajo, Medio, Alto, Crítico}; Probabilidad = {Baja, Media, Alta}. Nivel de riesgo calculado como combinación según el cuadrante.

| # | Hallazgo | Impacto | Probabilidad | Nivel de riesgo |
|---|----------|---------|--------------|-----------------|
| 1 | Contraseña débil `admin` | Crítico | Alta | **Crítico** |
| 5 | Sin MFA en accesos administrativos | Crítico | Alta | **Crítico** |
| 10 | Red plana / sin segmentación | Crítico | Alta | **Crítico** |
| 15 | Compromiso silencioso por punto ciego | Crítico | Alta | **Crítico** |
| 2 | SSH expuesto a `10.0.0.0/24` | Alto | Alta | **Alto** |
| 9 | Umbral de entropía fijo | Alto | Alta | **Alto** |
| 4 | SQLite sin cifrado en reposo | Alto | Media | **Alto** |
| 8 | API sin autenticación | Alto | Media | **Alto** |
| 11 | Fuerza bruta externa observada | Alto | Alta | **Alto** |
| 12 | Exfiltración observada | Crítico | Media | **Alto** |
| 13 | Manipulación de logs | Alto | Media | **Alto** |
| 14 | Creación de backdoor | Crítico | Media | **Alto** |
| 6 | Sin monitoreo 24/7 | Medio | Alta | **Medio** |
| 7 | Syslog en texto plano | Medio | Media | **Medio** |
| 3 | Certificado digital expirado | Bajo | Alta | **Medio** |

### Pregunta 6 — Priorización (más crítico → menos crítico)

1. **#1** Contraseña débil en `admin` — *Crítico*
2. **#5** Sin MFA en accesos administrativos — *Crítico*
3. **#10** Red plana sin segmentación — *Crítico*
4. **#15** Compromiso silencioso por punto ciego del detector — *Crítico*
5. **#9** Umbral de entropía fijo — *Alto*
6. **#2** SSH expuesto al exterior — *Alto*
7. **#11** Fuerza bruta observada — *Alto*
8. **#12** Exfiltración observada — *Alto*
9. **#14** Backdoor creado — *Alto*
10. **#13** Manipulación de logs — *Alto*
11. **#4** SQLite sin cifrado en reposo — *Alto*
12. **#8** API sin autenticación — *Alto*
13. **#7** Syslog en texto plano — *Medio*
14. **#6** Sin monitoreo humano 24/7 — *Medio*
15. **#3** Certificado digital expirado — *Medio*

### Pregunta 7 — Si solo pudiera corregir 3 problemas

**Elijo los hallazgos #1 (contraseña débil), #5 (sin MFA) y #10 (red plana sin segmentación).**

**Por qué estos tres:**

1. **#1 + #5 juntos rompen la cadena en el origen.** Todo el incidente del bloque 1 (login admin → brute force root → login exitoso → exfiltración → backdoor) **depende de que el atacante pudiera autenticarse con una sola credencial**. Si la contraseña fuera robusta Y hubiera un segundo factor, el evento `03:20 root login exitoso` simplemente no ocurre, y todo lo que vino después tampoco.
2. **#10 cierra el camino de red al atacante.** Aunque las credenciales fueran fuertes, una red plana permite que el atacante alcance servicios sensibles (SSH del router, dashboard, API). Segmentar con un jump host y ACLs entre `10.0.0.0/24` y la red de gestión obliga al atacante a comprometer múltiples saltos.
3. **No elegí #15 (el punto ciego del detector)** aunque también es crítico, porque arreglar la **detección** sin arreglar el **acceso** solo me da mejor visibilidad de un ataque que sigue siendo posible. Primero cierras la puerta; después mejoras el sensor.

En términos del marco CIA: corregir #1 y #5 protege **confidencialidad** e **integridad** desde el ingreso, y corregir #10 reduce drásticamente la **probabilidad** de que cualquier amenaza alcance los activos críticos. Estas tres correcciones combinadas habrían convertido el incidente de la sección 1 en una serie de intentos fallidos a las 03:10-03:17 que el detector estadístico habría visto, pero que nunca habrían escalado.

---

## 3. Cifrado y protección de datos

El enunciado del PDF lista tres tipos de información almacenada: **correos electrónicos, números de cuenta y documentos internos**. Para esta entrega se agregaron **tres tipos adicionales** propios del entorno Q-Sentinel: **contraseñas / hashes de usuarios, logs de auditoría syslog, y tokens de sesión / claves de API**.

### Pregunta 8 — ¿Qué información debería cifrarse y por qué?

| Tipo de dato | ¿Cifrar? | Justificación |
|--------------|----------|---------------|
| Correos electrónicos | **Sí** (en tránsito y reposo) | Contienen información personal identificable (PII) y conversaciones potencialmente sensibles. Su intercepción facilita phishing dirigido y suplantación. |
| Números de cuenta | **Sí** (especialmente en reposo) | Son datos financieros regulados (PCI-DSS, normativa local). Su exposición habilita fraude directo y la organización incurre en responsabilidad legal. |
| Documentos internos | **Sí** (selectivamente) | Pueden contener estrategia, propiedad intelectual o información competitiva. El cifrado limita el daño aun si hay una filtración de archivos. |
| Contraseñas / credenciales | **Sí, siempre como hash** (Argon2, bcrypt) más nunca en claro | Una contraseña en claro compromete cada cuenta que la reutilice. Por eso se almacenan como hashes con sal, no como cifrado reversible. |
| Logs de auditoría (syslog) | **Sí** (en tránsito con TLS/DTLS, en reposo el sqlite cifrado) | Los logs revelan la actividad real del sistema: usuarios, IPs, horarios, vulnerabilidades. Un atacante con acceso a logs sin cifrar conoce el camino al activo. En Q-Sentinel hoy `qsentinel.db` está en claro — es la vulnerabilidad #4. |
| Tokens de sesión / API keys | **Sí** (cifrados en reposo, transmitidos solo por canal TLS) | Son equivalentes a una contraseña activa: cualquier interceptación permite suplantar al usuario sin necesidad de credenciales. |

**Criterio general:** se cifra todo aquello cuya divulgación afecte directamente a **confidencialidad** (PII, financiero), o que comprometa el **acceso** futuro al sistema (credenciales, tokens), o que **revele la postura defensiva** (logs).

### Pregunta 9 — ¿Qué información podría enmascararse para análisis?

El cifrado no siempre es la respuesta correcta. Para análisis estadístico, capacitación, dashboards y entornos de desarrollo, suele convenir **enmascarar** (data masking) o **tokenizar** en lugar de cifrar:

| Tipo de dato | Forma de enmascaramiento sugerida |
|--------------|-----------------------------------|
| Correos electrónicos | `j****@dominio.com` — preserva el dominio para análisis, oculta la identidad. |
| Números de cuenta | Mostrar solo los últimos 4 dígitos: `**** **** **** 1234` (formato estándar PCI). |
| Documentos internos | Redactar nombres propios, números de proyecto y montos antes de compartir con auditores externos. |
| Contraseñas | **No se enmascaran, se hashean.** Nunca deben aparecer en análisis ni siquiera parcialmente. |
| Logs syslog | Sustituir IPs por hashes consistentes (`ip:185.32.44.10` → `ip:hash_3F2A`) — permite correlacionar el comportamiento de "una misma IP" sin revelar cuál. |
| Tokens / API keys | Mostrar prefijo + sufijo: `sk-ABCD…XY12`. Permite identificar la clave en logs sin reutilizarla. |

El **enmascaramiento es funcional**: deja al analista trabajar con datos útiles (patrones, agregados, correlaciones) sin exponer el dato sensible.

### Pregunta 10 — ¿Por qué el cifrado puede dificultar la analítica?

El cifrado de un dato lo vuelve **opaco** para cualquier proceso que no posea la clave. Eso protege la confidencialidad, pero impone costos analíticos concretos:

1. **No se pueden indexar ni buscar.** Un campo cifrado no responde a `WHERE email LIKE '%@empresa.com'` ni a búsquedas full-text. La consulta debe hacerse fuera del DBMS, descifrando en memoria — costoso e inseguro.
2. **No se pueden agregar (sum/avg/count distintivo) sin descifrar previamente.** Un dashboard sobre datos cifrados implica descifrar el conjunto completo en memoria; el riesgo se traslada al proceso analítico.
3. **Rompe los algoritmos estadísticos.** Q-Sentinel calcula entropía de Shannon sobre el mensaje. Si el syslog estuviese cifrado en tránsito sin que el listener tenga la clave, el detector vería bytes pseudoaleatorios uniformes — entropía artificialmente alta para todo y la detección colapsa.
4. **Aumenta la complejidad de las claves.** Si la clave se pierde o rota, datos legítimos quedan inaccesibles. La operación de un sistema cifrado es estructuralmente más frágil.
5. **Penaliza el rendimiento.** Cifrado/descifrado por cada lectura suma latencia. En streams de alta tasa (NetFlow, syslog masivo) puede ser inviable.

Por eso la práctica real es **combinar**: cifrar lo que debe permanecer secreto (PII, credenciales) y enmascarar lo que solo necesita ocultarse contextualmente (IPs, identificadores) — manteniendo la analítica viva sobre el resto.

---

## 4. Firma digital e integridad

### Demo práctica con SHA-3-256 sobre eventos reales

Para responder estas preguntas se ejecutó el script `scripts/actividad/demo_integridad.py`, que toma un evento real de la base de datos `qsentinel.db` y simula una manipulación. Output literal:

```
==============================================================================
FASE 1 — VERIFICACIÓN DE INTEGRIDAD DEL EVENTO ORIGINAL
==============================================================================
id evento         : 288
timestamp         : 2026-05-15 19:25:27.471
entropía          : 5.0360 bits
mensaje original  : <134>May 15 03:45:00 corp-srv auth: user=root
                    action="creacion usuario backdoor" src=185.32.44.10
                    sev=CRIT session=04073f8edd5826ac215c3705
                    req_id=bf7397a1d38b7e96 pid=46867
hash almacenado   : e9806c2c08e4c96c411841aac24c6328fb71bd5921d0dae18deff7849afcb229
hash recalculado  : e9806c2c08e4c96c411841aac24c6328fb71bd5921d0dae18deff7849afcb229
✅ COINCIDEN — el evento no ha sido alterado desde su captura.

==============================================================================
FASE 2 — SIMULACIÓN DE MANIPULACIÓN POST-CAPTURA
==============================================================================
mensaje manipulado: <...> user=r0ot action="creacion usuario backdoor" src=185.32.44.10 <...>
hash original     : e9806c2c08e4c96c411841aac24c6328fb71bd5921d0dae18deff7849afcb229
hash tras tampering: 14f9bf85b9e82c3cb55eaffe88e0fa78d24dc1ebb09c4f1dcbb6646098e52690

❌ DETECTADO — los hashes no coinciden.
   Coincidencias hex por azar: 4/64 caracteres.
```

### Pregunta 11 — ¿Cómo podría detectarse la modificación de un documento firmado?

El procedimiento técnico es el mismo que demostramos arriba con el evento 288:

1. **En el momento de la captura/firma:** se calcula el hash criptográfico del documento (en nuestro caso SHA-3-256 sobre el `raw_message`) y se almacena junto con el documento, o se firma con la clave privada del emisor.
2. **En el momento de la verificación:** se vuelve a calcular el hash sobre el contenido actual.
3. **Se comparan ambos hashes byte a byte.** Si coinciden → el documento es íntegro. Si difieren → el documento fue modificado, no importa cuán pequeña haya sido la alteración.

En la demo cambiamos exactamente **dos caracteres** (`root` → `r0ot`) y el hash resultante se parece al original solo en **4 de 64 caracteres hexadecimales**, prácticamente lo que esperaríamos por puro azar. Eso es el **efecto avalancha** de las funciones hash criptográficas: cualquier modificación, por mínima que sea, produce un resultado completamente distinto e impredecible.

### Pregunta 12 — ¿Qué papel juega el hash?

El hash es la **huella digital unívoca** del contenido. Cumple tres funciones simultáneas:

1. **Compresión irreversible.** Un mensaje de cualquier tamaño se reduce a 256 bits (en el caso de SHA-3-256). No es posible reconstruir el mensaje original a partir del hash — es una función de una sola vía.
2. **Identificación única.** Es computacionalmente inviable encontrar dos mensajes distintos que produzcan el mismo hash (resistencia a colisiones). Por eso un hash puede servir como "etiqueta" del contenido.
3. **Detector de cambios.** Cualquier modificación del mensaje, aunque sea de un solo bit, altera de forma drástica e impredecible el hash resultante. Hace imposible "ajustar" un mensaje manipulado para que conserve el hash original.

En Q-Sentinel cada evento syslog se hashea con SHA-3-256 al momento de la captura y el hash se persiste junto con el mensaje. Esa cadena de custodia es lo que garantiza que cualquier intento posterior de manipular la base de datos sea detectable.

### Pregunta 13 — ¿Qué garantiza la firma digital?

Una firma digital combina el hash con criptografía asimétrica (clave privada del firmante). Lo que **garantiza** es:

| Propiedad | Qué significa | Cómo se logra |
|-----------|---------------|----------------|
| **Integridad** | El contenido no fue modificado desde que se firmó. | El hash forma parte de la firma; si el contenido cambia, el hash cambia, y la verificación falla. |
| **Autenticidad** | La firma proviene realmente del emisor que dice ser. | Solo el poseedor de la clave privada puede generar una firma que la clave pública correspondiente valide. |
| **No repudio** | El firmante no puede negar después haber firmado el documento. | Como la clave privada es exclusiva del firmante, una firma válida es prueba criptográfica de que él la generó. |

Lo que la firma digital **no garantiza por sí sola**: confidencialidad. Un documento firmado puede leerse libremente — la firma protege contra alteración y suplantación, no contra divulgación. Para esto último se combina con cifrado.

Aplicado a nuestro entorno: aunque Q-Sentinel hoy solo hashea (no firma con clave asimétrica), agregar firma digital sobre la cadena de hashes — algo trivial de implementar — convertiría la base de datos de eventos en evidencia forense admisible: nadie podría modificar los logs sin invalidar la firma, y nadie podría falsificar logs nuevos sin la clave privada del sistema.

---

## 5. Preguntas finales

### Pregunta 14 — ¿Por qué la analítica no reemplaza los controles de seguridad?

La analítica **detecta**, los controles **previenen y bloquean**. Son funciones complementarias, no sustitutas. El propio incidente que reconstruimos en la sección 1 lo demostró empíricamente:

1. **La analítica tiene puntos ciegos.** Q-Sentinel marcó 10 de los 11 eventos sospechosos como anomalía (H > 5.0 bits). El que no marcó (`03:20 root login exitoso`) era justamente el **momento crítico del ataque**. Un atacante consciente del modelo de detección puede modular sus mensajes para mantenerlos estadísticamente "normales" y evadirla. Esa es una limitación estructural, no un bug.
2. **La analítica trabaja en pasado o presente; los controles cierran el futuro.** Cuando Sentinel detecta una anomalía, el evento **ya ocurrió**: la descarga ya pasó, el login ya se completó. La respuesta automática (ACL en R1) es reactiva. Un control preventivo — MFA, segmentación de red, política de contraseñas robustas — habría impedido que el evento se produjera en primer lugar.
3. **La analítica depende de la integridad de sus propios datos.** Si los logs llegan en texto plano (vulnerabilidad #7 de la sección 2), o si la BD `qsentinel.db` no está cifrada (vuln. #4), un atacante puede manipular la entrada del sistema y hacer que la analítica vea exactamente lo que el atacante quiere que vea. Sin controles que protejan la integridad de la cadena, la analítica se vuelve teatro.
4. **Los modelos requieren mantenimiento.** El umbral H > 5.0 funciona hoy; si mañana cambia el patrón de tráfico normal, generará falsos positivos o falsos negativos. Los controles, una vez implementados correctamente, no se "desentrenan".
5. **Hay decisiones que la analítica no puede tomar.** Un sistema estadístico no sabe si un usuario tiene autorización para acceder a una tabla a las 03:00 AM. Esa autorización vive en políticas, no en patrones. Solo un control de acceso explícito puede aplicarla.

**Conclusión:** la analítica es el sensor; los controles son la armadura. Un sistema serio necesita ambos — y un humano que los interprete cuando entran en conflicto.

### Pregunta 15 — ¿Qué habilidades necesita un analista de seguridad de datos?

A partir de la experiencia construyendo y operando Q-Sentinel durante este proyecto, identifico cinco habilidades que resultaron indispensables:

1. **Pensamiento estadístico y probabilístico.** No basta con saber qué es la entropía de Shannon — hay que entender cuándo aplica, cuándo falla y cómo elegir umbrales que balancean falsos positivos con falsos negativos. El caso del evento `03:20` no se entiende sin saber qué mide realmente el algoritmo.
2. **Fundamentos de redes y sistemas.** Leer un syslog implica entender qué es facility, severity, una IP enrutable vs RFC1918, una ACL, una VLAN, un puerto bien conocido. Sin esa base, no se puede correlacionar un evento con su significado operativo (ej. "SSH desde 10.0.0.2 hacia R1" requiere saber qué es R1, qué es SSH y por qué 10.0.0.2 es zona externa).
3. **Programación práctica (no académica).** Python para procesar logs y prototipar detectores, JavaScript para visualizar en tiempo real, SQL para consultar persistencia. La diferencia entre "saber programar" y "saber escribir herramientas que aceleren la respuesta a un incidente real" es enorme. Un analista que no automatiza repite errores manuales bajo presión.
4. **Criptografía aplicada.** Distinguir entre cifrado, hash y firma digital; saber por qué se eligió SHA-3 sobre MD5 (resistencia post-cuántica); entender qué garantiza una cadena de hashes y qué no. Sin esto no se puede defender la integridad de la evidencia ante un proceso legal o una auditoría.
5. **Pensamiento adversarial.** Preguntarse permanentemente *"¿cómo evadiría esto un atacante?"*. Esa pregunta es la que reveló el punto ciego del detector estadístico en este mismo lab. Un analista que solo verifica que las cosas funcionan, pero nunca verifica que se puedan engañar, es incompleto.

Habilidades secundarias pero importantes: comunicación escrita (reportar incidentes con claridad y sin ruido), gestión del tiempo bajo estrés (un incidente real no espera), y conocimiento de regulación local (qué hay que reportar, a quién, en cuánto tiempo).

### Pregunta 16 — ¿Qué aprendí durante el semestre que considero más importante?

> **Personalizar con tu voz.** Esta pregunta es individual; los bullets de abajo son sugerencias para que estructures tu respuesta, no la respuesta en sí. Bórralos cuando termines.

Posibles ejes para articular la respuesta:

- **El choque entre teoría y práctica.** Saber qué es el principio CIA en clase es una cosa; ver cómo se vulnera en un log real de tu propio lab es otra. ¿Qué concepto cambió de significado cuando lo viste en acción?
- **La detección no es trivial.** Construir Q-Sentinel demostró que un detector estadístico puede tener un punto ciego justo en el evento más crítico. ¿Qué te dejó ese hallazgo?
- **El valor de equivocarte con seguridad.** El lab EVE-NG te permitió simular ataques, romper cosas, modificar configuraciones de Cisco — sin consecuencias reales. ¿Qué experimento te sirvió más?
- **La integración multi-disciplinar.** Para responder a una sola pregunta del PDF terminamos tocando: Python, redes Cisco, criptografía, SQL, estadística, frontend, regulación. ¿Cuál de esas combinaciones te resultó más reveladora?
- **El cambio en tu forma de leer logs.** Probablemente antes del semestre un log era texto. Ahora es evidencia. ¿Cuándo notaste el cambio?

Estructura sugerida: un párrafo introductorio diciendo cuál fue el aprendizaje principal en una frase, un párrafo de desarrollo con la experiencia concreta que lo respalda (idealmente del lab Q-Sentinel), y un párrafo final con cómo eso te marca el siguiente paso (qué quieres profundizar en el próximo semestre / dónde quieres aplicarlo profesionalmente).

---

## Anexos

- **Código del proyecto Q-Sentinel:** `c:\dev\Sentinel`
- **Script de inyección syslog:** `scripts/actividad/inyectar.py` — envía los 25 registros del dataset al listener UDP/514.
- **Dataset analizado:** `scripts/actividad/logs_actividad.txt`
- **Demo de integridad SHA-3:** `scripts/actividad/demo_integridad.py` — reproduce el experimento de la sección 4.
- **Persistencia de eventos:** `qsentinel.db` (SQLite WAL).
- **Endpoints consultados para evidencia:**
  - `GET /api/history?anomaly_only=true&limit=50` — listado de anomalías detectadas.
  - `GET /api/history?limit=50` — listado completo de eventos procesados.
- **Topología del lab:** `topology.yaml`, simulada en EVE-NG.

*Todo el material es reproducible: iniciar `python server.py`, ejecutar `python scripts/actividad/inyectar.py`, abrir `http://localhost:8000` y consultar la BD con `python scripts/actividad/demo_integridad.py`.*


