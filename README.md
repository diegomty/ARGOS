# Q-Sentinel

**Plataforma de Visualización SOC con Inmunidad Digital Adaptativa**

Q-Sentinel es una herramienta de defensa proactiva que evoluciona del paradigma de IDS por firmas hacia un modelo de **inmunidad digital adaptativa**: detecta anomalías midiendo la complejidad estadística (entropía de Shannon) de los logs en tiempo real, correlaciona el origen del ataque, aplica contramedidas autónomas vía SSH sobre infraestructura Cisco, y todo ello se observa y opera desde un **digital twin 3D interactivo** del segmento de red.

No es solo monitoreo pasivo. El operador puede **tocar un departamento en la visualización 3D para aislar su VLAN en vivo** (touch-to-isolate), ver flujos NetFlow reales animados como partículas viajando entre nodos, e interrogar el histórico forense almacenado en SQLite.

---

## Stack técnico

| Capa | Tecnología |
| :--- | :--- |
| Backend | Python 3.13 · FastAPI · Uvicorn · WebSockets |
| Telemetría | Syslog UDP/514 · NetFlow v9 UDP/2055 (parser propio) |
| Persistencia | SQLite (WAL mode) |
| Automatización de red | Paramiko (SSH) sobre Cisco IOS |
| Criptografía | SHA-3-256 (cadena de custodia post-cuántica) |
| Frontend | Three.js 0.169 (WebGL · ES modules · CSS2DRenderer) |
| Infra de prueba | EVE-NG · Cisco 7200 IOS 15 · IOSvL2 · VPCS · Kali Linux |

---

## Arquitectura

```
+---------------------------+      +-----------------------------+
|      LAB EVE-NG           |      |    Q-Sentinel (server.py)   |
|                           |      |                             |
|  Router Cisco 7200        |      |  +-----------------------+  |
|  +----------------------+ |      |  | Syslog listener UDP/514|  |
|  | NetFlow v9 + Syslog  | -syslog->|  +-----------------------+ |
|  |  + SSH server        | -netflow->|+----------------------+   |
|  +----------+-----------+ |  SSH  ||| NetFlow listener     |   |
|             |             |  <-----||+----------------------+   |
|       trunk |             |       |  +-----------------------+  |
|             v             |       |  | Motor estadistico    |  |
|  +----------------------+ |       |  | (entropia + SHA-3)   |  |
|  |      SW1 IOSvL2      | |       |  +-----------------------+  |
|  +----------------------+ |       |  +-----------------------+  |
|  | VLAN 10-60: deptos   | |       |  | Responder (Paramiko) |  |
|  +----------------------+ |       |  +-----------------------+  |
|                           |       |  +-----------------------+  |
|  + Zona externa (10.0/24) |       |  | Storage SQLite (WAL) |  |
|  + Atacante (Kali)        |       |  +-----------+-----------+  |
+---------------------------+       +--------------|--------------+
                                                   | WebSocket
                                                   v
                                +------------------+-------------+
                                |  Digital Twin (Three.js)       |
                                |  - Icosaedro + simplex shader  |
                                |  - 17 nodos topologicos        |
                                |  - Touch-to-isolate (raycaster)|
                                |  - Particulas NetFlow en vivo  |
                                |  - Dashboard SHA-3 / SSH / IPs |
                                |  - Chart de entropia 30-min    |
                                +--------------------------------+
```

---

## Fases implementadas

### A. Percepción (syslog)
Listener UDP/514 sin bloqueo, timestamps con precisión de milisegundos. Cada datagrama del router se decodifica y pasa al pipeline estadístico.

### B. Motor estadístico
- **Entropía de Shannon:** `H(X) = -Σ P(xi) log₂ P(xi)` calculada sobre los caracteres del mensaje. Detecta mensajes anormalmente caóticos sin necesidad de firmas.
- **SHA-3-256:** hash criptográfico de cada log para garantizar integridad inmutable de la cadena forense.

### C. Inteligencia y filtrado
- **Whitelist heurística** que descarta ruido operativo conocido (CDP, SSH, TFTP, restart events).
- **Correlación de capa 3:** regex sobre el cuerpo del mensaje para extraer la IP atacante incluso cuando el reporte del router la oculta como `UNKNOWN` (Plan B: subred fallback).

### D. Respuesta autónoma
Cuando `H > 5.0` y el origen no es whitelisted, el sistema se conecta vía SSH al router con `paramiko.invoke_shell()` y aplica una ACL extendida (`deny ip host <ip> any`) en la interfaz externa. Persiste con `write memory`.

### E. Visualización 3D
FastAPI sirve un frontend Three.js que renderiza un icosaedro con shader vertex de simplex 3D — la membrana respira y cambia de color (cian → ámbar → rojo) según la entropía media reciente. Dashboard lateral con cadena SHA-3 en vivo, IPs neutralizadas y consola SSH.

### F. Digital twin
Modelo declarativo en `topology.yaml` (17 nodos, 16 links) → renderizado 3D dentro del icosaedro:
- Departamentos como cubos de colores en anillo (Finanzas, RR.HH., TI, I+D, Producción, Ventas)
- Switch central + router + zona externa
- Links curvos (Bezier) con grosor por tipo (trunk grueso cian, access tenue, external rojo)
- Etiquetas CSS2D que siempre miran a cámara

### G. Touch-to-isolate
Raycaster sobre el canvas → click en un departamento abre modal con su VLAN/subred/interfaz → acción "AISLAR SEGMENTO" ejecuta `shutdown` en el subif Cisco vía SSH. Estado sincronizado entre todas las pestañas vía WebSocket. Visualmente el nodo aislado se encoge, se tinta gris con halo rojo pulsante, y los links que lo tocan se vuelven rojos pulsantes.

### H. Persistencia y forensia temporal
SQLite WAL almacena:
- `events`: cada SentinelEvent con timestamp, entropía, SHA-3, IP, plan, blocked.
- `flows`: NetFlow histórico enriquecido con `src_node`/`dst_node` de la topología.
- `isolation_log`: auditoría de cada acción manual aislar/reactivar.

Endpoints REST: `/api/history`, `/api/timeseries`, `/api/flows`, `/api/isolation-history`. Chart SVG en la UI muestra entropía agregada (avg/max) de los últimos 30 minutos con marcadores rojos por bucket anómalo.

### I. NetFlow v9 en vivo
Listener UDP/2055 con **parser propio** (RFC 3954). Las librerías de PyPI rompen con la salida de IOS Cisco 7200 — incluido un manejo de templates con cache persistente y deduplicación por 5-tupla (porque IOS exporta dos veces cuando hay `ip flow` en ingress y egress de subifs distintos del path).

Cada flujo se enriquece con info de topología (`src_node`, `dst_node`), se persiste y se broadcastea por WS. El frontend lo materializa como una partícula con color según protocolo (ICMP naranja, TCP cian, UDP morado) viajando a lo largo de una curva CatmullRom desde el departamento origen, pasando por SW1 (o R1 si es tráfico al/del perímetro), hasta el departamento destino.

---

## Estructura del proyecto

```
Q-Sentinel/
├── Sentinel.py            # CLI listener autónomo (compatibilidad)
├── server.py              # Entrypoint FastAPI + WS + StaticFiles
├── topology.yaml          # Modelo declarativo de la red
├── requirements.txt
├── core/
│   ├── analysis.py        # Entropia + SHA-3 + correlacion L3
│   ├── config.py          # Constantes + overrides por env vars
│   ├── events.py          # SentinelEvent dataclass
│   ├── flowlistener.py    # Parser NetFlow v9 propio
│   ├── responder.py       # SSH automation contra Cisco
│   ├── storage.py         # SQLite WAL + queries
│   └── topology.py        # Modelo de topologia + lookups por IP
├── web/
│   ├── index.html         # Shell + importmap Three.js
│   ├── style.css          # Tema dark SOC
│   └── js/
│       ├── main.js        # Entrypoint: WS + render loop + raycaster
│       ├── state.js       # H suavizada (EMA), pulsos con decay
│       ├── viewMesh.js    # Icosaedro + simplex shader + CSS2DRenderer
│       ├── topologyLayer.js  # Nodos 3D + links + particulas de flujo
│       ├── dashboard.js   # Paneles laterales (SHA-3, IPs, SSH)
│       ├── chart.js       # SVG timeseries (30 min)
│       ├── ticker.js      # Feed inferior horizontal
│       └── modal.js       # Modal de aislamiento
└── scripts/
    └── test_flow_listener.py   # Smoke test standalone del NetFlow
```

---

## Setup local

### Requisitos

- Python 3.10+ (probado en 3.13)
- Permisos para escuchar en UDP/514 (admin en Windows, root o `setcap` en Linux)
- Un router Cisco accesible vía SSH (o lab EVE-NG con el setup descrito abajo)

### Instalación

```bash
git clone https://github.com/diegomty/Q-Sentinel.git
cd Q-Sentinel
python -m venv .venv
.venv\Scripts\activate    # Windows
# source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
```

### Configuración

Las credenciales del router se sobreescriben con variables de entorno:

```bash
$env:Q_SENTINEL_ROUTER_USER = "admin"
$env:Q_SENTINEL_ROUTER_PASS = "tu-password-real"
```

Los defaults en `core/config.py` (`admin`/`root`) son solo para el lab EVE-NG; no son credenciales reales.

### Ejecución

```bash
python server.py
```

Abre el navegador en `http://localhost:8000`. Frontend Three.js + dashboard live.

---

## Lab EVE-NG de referencia

| Componente | Detalle |
| :--- | :--- |
| R1 | Cisco 7200 IOS 15 · f0/0=mgmt · f1/0=trunk · f2/0=external |
| SW1 | IOSvL2 con 6 VLANs (10, 20, 30, 40, 50, 60) |
| Hosts | 6 VPCS, uno por VLAN, IP `.10` |
| Atacante | Kali Linux en VMnet host-only o segmento externo `10.0.0.0/24` |
| Sentinel | El propio PC del operador en la subred de mgmt `192.168.128.0/24` |

Configuración mínima de R1 para enviar todo a Q-Sentinel:

```cisco
logging host 192.168.128.1
service timestamps log datetime msec
ip flow-export version 9
ip flow-export destination 192.168.128.1 2055
ip flow-export template refresh-rate 3
```

Y en cada subinterfaz a observar:

```cisco
interface f1/0.10
 ip flow ingress
 ip flow egress
```

---

## Roadmap

- **Fase J** — ML adaptativo: Isolation Forest entrenado en CICIDS2017 (o sobre el corpus local que se acumula en SQLite) para complementar el threshold fijo de entropía con detección probabilística.
- **Fase K** — Deep Packet Inspection con Scapy: análisis del payload de paquetes capturados en vivo, no solo del metadata de syslog/NetFlow.
- **Bonus** — Adaptador SOAR pluggable: la actual `responder.py` solo habla Cisco IOS. Abstraer la interfaz para soportar Fortinet, Palo Alto, soluciones SDN.
- **Bonus** — Dockerfile + docker-compose para arranque one-shot.

---

## Notas técnicas relevantes

- **NetFlow v9 parser:** la librería `netflow` de PyPI tiene un `IndexError` con la salida específica de IOS 15 en el 7200. El parser de [core/flowlistener.py](core/flowlistener.py) se implementó desde cero siguiendo RFC 3954.
- **Dedupe NetFlow:** habilitar `ip flow ingress` y `ip flow egress` en subifs distintos del mismo path hace que IOS exporte cada paquete dos veces. El listener deduplica por 5-tupla en ventana de 3 segundos.
- **Threading:** los listeners (syslog, NetFlow) corren en threads daemon. Los callbacks usan `asyncio.run_coroutine_threadsafe` para reinyectar al event loop de FastAPI sin lock contention.
- **WebSocket envelope:** mensajes con `{kind, payload}` para multiplexar tres canales (`event`, `topology_state`, `flow`) sobre una sola conexión por cliente.

---

## Licencia

Proyecto personal de portfolio. Uso libre con atribución.
