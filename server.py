"""Q-Sentinel — Servidor FastAPI + WebSocket para la Fase E.

Arquitectura: un único proceso. El listener UDP corre en un thread
daemon; cada `SentinelEvent` que produce se serializa a JSON y se
broadcastea por WebSocket a todos los clientes conectados.

Ejecutar:
    python server.py
    # → frontend en  http://<ip-local>:8000
    # → websocket en ws://<ip-local>:8000/ws
"""

import asyncio
import os
import threading
import warnings
from collections import deque

# scikit-learn emite un UserWarning por cada predicción cuando el estimador usa
# joblib con n_jobs distinto de 1 (aviso interno de la librería, sin impacto).
# Como el detector evalúa CADA flujo, ensuciaba la consola: lo silenciamos.
warnings.filterwarnings("ignore", message=r".*delayed.*Parallel.*")
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Deque, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from Sentinel import iniciar_q_sentinel
from core import topology as topology_mod
from core.analysis import hash_sha3
from core.events import SentinelEvent
from core.flowlistener import FlowListener
from core.honeypot import HoneypotListener, DEFAULT_DECOYS
from core.soar import SoarEngine
from core.storage import Storage
from core.topology import Topology
from ml.detector import HybridDetector

# Persistencia: SQLite WAL en `qsentinel.db`. Se inicializa al import,
# antes de que arranque el listener, para que los esquemas existan.
storage = Storage()

# Detector ML híbrido (Fase J): modelo heredado CICIDS + línea base local.
# Si el .joblib no existe o la línea base es chica, degrada con gracia
# (ver ml/detector.py) — el servidor arranca igual.
detector = HybridDetector()

# Cada cuánto se re-entrena la línea base local con la ventana móvil.
ML_RETRAIN_INTERVAL_S = 6 * 3600

# Motor SOAR (respuesta automática): decide y ejecuta el bloqueo de IPs
# atacantes en el firewall local. Arranca en modo MANUAL (seguro); se puede
# arrancar en automático con SOAR_MODE=auto. La lista blanca (gateway, IP
# propia, DNS…) se detecta sola para que sea imposible auto-suicidar la red.
soar = SoarEngine()
if os.getenv("SOAR_MODE", "").strip().lower() == "auto":
    try:
        soar.set_mode("auto")
    except ValueError:
        pass


# Topología cargada una sola vez al startup. Si falla la carga, el
# resto del servidor (listener, WS, dashboard) sigue funcionando y
# `/api/topology` responde 503 hasta que se arregle el YAML.
_topology: Topology | None = None
_topology_error: str | None = None
try:
    _topology = topology_mod.load()
    print(
        f"[server] topología cargada: {_topology.name} v{_topology.version} "
        f"({len(_topology.nodes)} nodos, {len(_topology.links)} links)",
        flush=True,
    )
except Exception as e:  # FileNotFoundError, ValueError, yaml.YAMLError, …
    _topology_error = f"{type(e).__name__}: {e}"
    print(f"[server] WARNING: no se pudo cargar topology.yaml — {_topology_error}", flush=True)


# El historial sirve para que un cliente que se conecta tarde a la demo
# vea los últimos eventos de contexto en lugar de una pantalla muerta.
HISTORIAL_MAX = 100


class ConnectionManager:
    """Gestiona el conjunto de WS clientes + estadísticas + estado del lab.

    Los mensajes que envía siguen un envelope `{kind, payload}`:
      * `kind="event"` → SentinelEvent serializado (pipeline original)
      * `kind="topology_state"` → cambio en `isolated_segments`
    """

    def __init__(self) -> None:
        self.active: List[WebSocket] = []
        self.history: Deque[dict] = deque(maxlen=HISTORIAL_MAX)
        self.total_eventos = 0
        self.total_anomalias = 0
        self.ips_bloqueadas: List[str] = []
        # Conjunto de node_ids de la topología que están aislados (subif
        # en `shutdown`). El frontend lo refleja con tinte gris + halo rojo.
        self.isolated_segments: set[str] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self.active.append(ws)
            # 1) Reproduce historial de eventos para que la UI no se vea muerta
            for msg in self.history:
                try:
                    await ws.send_json(msg)
                except Exception:
                    break
            # 2) Estado actual de aislamiento — para que pestañas tardías
            #    pinten correctamente los nodos que ya están "shutdown".
            try:
                await ws.send_json({
                    "kind": "topology_state",
                    "payload": {"isolated": sorted(self.isolated_segments)},
                })
            except Exception:
                pass

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    def record_event(self, payload: dict) -> None:
        """Actualiza contadores agregados a partir de un SentinelEvent."""
        self.total_eventos += 1
        if payload.get("is_anomaly"):
            self.total_anomalias += 1
        if payload.get("blocked") and payload.get("attacker_ip"):
            ip = payload["attacker_ip"]
            if ip not in self.ips_bloqueadas:
                self.ips_bloqueadas.append(ip)

    async def broadcast(self, msg: dict) -> None:
        """Envía un envelope `{kind, payload}` a todos los clientes vivos."""
        async with self._lock:
            self.history.append(msg)
            muertos: List[WebSocket] = []
            for ws in self.active:
                try:
                    await ws.send_json(msg)
                except Exception:
                    muertos.append(ws)
            for ws in muertos:
                self.active.remove(ws)


manager = ConnectionManager()

# Hidratamos contadores con los totales históricos de la DB. Sin esto,
# tras un restart el dashboard mostraría "0 eventos" hasta que llegue
# tráfico nuevo, dando una falsa sensación de pérdida de datos.
try:
    _persisted = storage.stats()
    manager.total_eventos = _persisted["total_events"]
    manager.total_anomalias = _persisted["total_anomalies"]
    print(
        f"[server] storage hidratado: {_persisted['total_events']} eventos "
        f"({_persisted['total_anomalies']} anomalías) ya en DB",
        flush=True,
    )
except Exception as e:
    print(f"[server] WARNING: no se pudo hidratar contadores desde DB — {e}", flush=True)


_flow_listener: Optional[FlowListener] = None
_honeypot: Optional[HoneypotListener] = None
_sensor = None
# El sensor de captura pasiva es OPT-IN porque requiere admin: se activa
# arrancando el servidor con la variable de entorno Q_SENTINEL_SENSOR=1.
SENSOR_ENABLED = os.getenv("Q_SENTINEL_SENSOR", "0") == "1"
# Interfaz a capturar por el sensor. Sin esto, scapy elige la del route por
# defecto (p. ej. Wi-Fi). En un despliegue con varias NICs (VMnet, etc.) hay
# que apuntarlo a la del segmento monitoreado: Q_SENTINEL_IFACE="VMnet8".
SENSOR_IFACE = os.getenv("Q_SENTINEL_IFACE") or None


def _soar_log_lines(res: dict, ip: str) -> List[str]:
    """Convierte el veredicto del SOAR en líneas para el `response_log` del evento."""
    if res.get("deduped"):
        return [f"[soar] {ip} ya estaba bloqueada — sin cambios (no se re-aplica la regla)"]
    action = res.get("action")
    if action == "blocked":
        return [f"[soar] AUTO-BLOQUEO de {ip} aplicado en el firewall",
                f"  $ {res.get('command', '')}"]
    if action == "block_failed":
        return [f"[soar] auto-bloqueo de {ip} FALLÓ (¿el servidor corre como admin/root?)",
                f"  $ {res.get('command', '')}"]
    if action == "skipped":
        return [f"[soar] {ip} NO se bloquea: {res.get('reason', '')}"]
    # action == "surfaced" -> modo manual, la decisión es del operador
    if res.get("blockable"):
        return [f"[soar] modo manual — {ip} es candidata a bloqueo (usa «Bloquear»)"]
    return [f"[soar] modo manual — {ip} está en lista blanca ({res.get('reason', '')})"]


def _handle_flow(flow: dict, loop: asyncio.AbstractEventLoop) -> None:
    """Procesa un flujo venga de donde venga (NetFlow O el sensor pasivo):
    lo enriquece con topología, lo persiste en SQLite, lo evalúa con el
    detector ML híbrido y lo difunde por WebSocket. Punto único para que
    ambas fuentes de flujos entren al pipeline por la misma puerta.
    """
    # Enriquecer con topología — si la IP cae en un segmento declarado.
    if _topology is not None:
        src_dept = _topology.department_for_ip(flow["src_ip"])
        dst_dept = _topology.department_for_ip(flow["dst_ip"])
        flow["src_node"] = src_dept.id if src_dept else None
        flow["dst_node"] = dst_dept.id if dst_dept else None
    else:
        flow["src_node"] = None
        flow["dst_node"] = None

    try:
        storage.save_flow(flow)
    except Exception as e:
        print(f"[storage] save_flow ERROR: {e}", flush=True)

    # Veredicto ML híbrido (sklearn por fila es ~1 ms).
    try:
        flow["ml"] = detector.evaluate(flow)
    except Exception as e:
        print(f"[ml] evaluate ERROR: {e}", flush=True)
        flow["ml"] = None

    # Difusión por WS solo para flujos que mapean a la topología declarada.
    if flow["src_node"] and flow["dst_node"] and flow["src_node"] != flow["dst_node"]:
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"kind": "flow", "payload": flow}),
            loop,
        )


def _arrancar_flow_listener(loop: asyncio.AbstractEventLoop) -> Optional[FlowListener]:
    """Lanza el listener NetFlow UDP/2055 en un thread daemon."""
    listener = FlowListener(host="0.0.0.0", port=2055)
    listener.start(lambda flow: _handle_flow(flow, loop))
    print("[server] listener NetFlow arrancado en thread daemon", flush=True)
    return listener


def _arrancar_sensor(loop: asyncio.AbstractEventLoop):
    """Sensor de captura pasiva (OPT-IN). Alimenta el pipeline con los flujos
    REALES de la red del host — así el Mapa y el detector dejan de depender de
    que un router exporte NetFlow.

    Requiere que el servidor corra COMO ADMINISTRADOR (captura de paquetes) y
    Npcap/libpcap. Se activa con la variable de entorno Q_SENTINEL_SENSOR=1.
    Si algo falla, degrada con gracia sin tumbar el servidor.
    """
    def _on_identity(ip, mac, hostname, source, device_type=None):
        # Nombre/MAC/tipo observados pasivamente (DHCP/mDNS/SSDP) -> identidades.
        try:
            storage.upsert_identity(ip, mac=mac, hostname=hostname, source=source,
                                    device_type=device_type)
        except Exception:
            pass

    def _on_alert(alert):
        # Ataque por TASA (flood/DoS) detectado por el sensor -> evento anómalo,
        # igual que un hit de honeypot: persiste, cuenta y se emite por WebSocket
        # (aparece en Anomalías, sube KPIs y pulsa en rojo en el Gemelo).
        ip = alert["src_ip"]
        msg = (f"DoS FLOOD {ip} -> {alert['dst_ip']}:{alert['dst_port']} "
               f"{alert['pps']} paq/s ({alert['protocol']}, ~{alert.get('avg_bytes', '?')}B/paq)")
        # SOAR: en modo auto bloquea la IP (según política); en manual solo la expone.
        soar_res = soar.on_detection(ip, reason="dos-flood", kind="dos-flood")
        rlog = [f"[dos] flood detectado: {alert['pps']} paq/s hacia "
                f"{alert['dst_ip']}:{alert['dst_port']}"]
        rlog += _soar_log_lines(soar_res, ip)
        ev = SentinelEvent(
            timestamp=alert["timestamp"],
            raw_message=msg,
            source_ip=ip,
            entropy=6.8,               # muy alta: un flood sostenido es severo
            sha3=hash_sha3(msg),
            is_trusted=False,
            is_anomaly=True,
            attacker_ip=ip,
            plan="A",
            blocked=bool(soar_res.get("blocked")),
            response_log=rlog,
        )
        payload = ev.to_dict()
        try:
            storage.save_event(payload)
        except Exception as e:
            print(f"[storage] save_event (dos) ERROR: {e}", flush=True)
        manager.record_event(payload)
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"kind": "event", "payload": payload}), loop)

    try:
        from core.sensor import PassiveSensor  # import perezoso (scapy)
        sensor = PassiveSensor(iface=SENSOR_IFACE)
        sensor.start(lambda flow: _handle_flow(flow, loop),
                     on_identity=_on_identity, on_alert=_on_alert)
        # Al bloquear/desbloquear una IP, el SOAR le avisa al sensor para que
        # deje de procesar (o vuelva a vigilar) su tráfico. Así un atacante
        # bloqueado no genera re-detecciones ni puede saturar el sensor.
        soar.on_block_change = lambda ip, active: (
            sensor.ignore_source(ip) if active else sensor.unignore_source(ip))
        print(f"[server] sensor de captura pasiva arrancado "
              f"(iface={SENSOR_IFACE or 'default'})", flush=True)
        return sensor
    except Exception as e:
        print(f"[sensor] no se pudo iniciar (¿admin? ¿Npcap? ¿scapy?): {e}", flush=True)
        return None


def _arrancar_listener(loop: asyncio.AbstractEventLoop) -> threading.Thread:
    """Lanza el listener UDP en un thread daemon.

    El callback `on_event` se invoca desde un contexto sync; usamos
    `run_coroutine_threadsafe` para reinyectar el broadcast en el event
    loop asyncio del proceso principal.
    """

    def on_event(ev: SentinelEvent) -> None:
        payload = ev.to_dict()
        # Persistimos ANTES de broadcastear: si el lock de SQLite tarda un
        # par de ms, prefiero retraso de UI a perder el evento de la DB.
        try:
            storage.save_event(payload)
        except Exception as e:  # nunca romper el listener por la DB
            print(f"[storage] save_event ERROR: {e}", flush=True)
        manager.record_event(payload)
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"kind": "event", "payload": payload}),
            loop,
        )

    thread = threading.Thread(
        target=iniciar_q_sentinel,
        kwargs={"on_event": on_event},
        daemon=True,
        name="q-sentinel-listener",
    )
    thread.start()
    print("[server] listener UDP arrancado en thread daemon", flush=True)
    return thread


def _arrancar_honeypot(loop: asyncio.AbstractEventLoop) -> HoneypotListener:
    """Lanza el honeypot. Cada conexión a un señuelo es una amenaza REAL de
    alta confianza (nadie legítimo toca un servicio falso), así que la
    convertimos en un SentinelEvent anómalo y la inyectamos al mismo pipeline
    que los eventos de syslog: persiste, cuenta y se emite por WebSocket.
    """

    def on_hit(hit: dict) -> None:
        ip = hit["src_ip"]
        msg = (f"HONEYPOT {hit['service']}:{hit['dst_port']} <- "
               f"{ip}:{hit['src_port']} "
               f"data={hit['data'][:120] or '(sin datos)'}")
        # SOAR: un hit de honeypot es amenaza de máxima confianza (nadie legítimo
        # toca un señuelo). En modo auto se bloquea; en manual solo se expone.
        soar_res = soar.on_detection(ip, reason="honeypot", kind="honeypot")
        rlog = [f"[honeypot] señuelo '{hit['service']}' tocado en puerto {hit['dst_port']}"]
        rlog += _soar_log_lines(soar_res, ip)
        ev = SentinelEvent(
            timestamp=hit["timestamp"],
            raw_message=msg,
            source_ip=ip,
            entropy=6.5,               # alta: un hit de honeypot es severidad máxima
            sha3=hash_sha3(msg),
            is_trusted=False,
            is_anomaly=True,
            attacker_ip=ip,
            plan="A",
            blocked=bool(soar_res.get("blocked")),
            response_log=rlog,
        )
        payload = ev.to_dict()
        try:
            storage.save_event(payload)
        except Exception as e:
            print(f"[storage] save_event (honeypot) ERROR: {e}", flush=True)
        manager.record_event(payload)
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"kind": "event", "payload": payload}),
            loop,
        )

    hp = HoneypotListener()
    hp.start(on_hit)
    print("[server] honeypot arrancado (señuelos activos)", flush=True)
    return hp


async def _ml_retrain_loop() -> None:
    """Re-entrena la línea base local cada ML_RETRAIN_INTERVAL_S.

    El primer entrenamiento corre al arranque (con lo que haya en la DB);
    los siguientes mantienen la ventana móvil fresca. `to_thread` evita
    bloquear el event loop durante el fit (segundos con 50k flujos).
    """
    while True:
        try:
            await asyncio.to_thread(detector.retrain_local, storage)
        except Exception as e:
            print(f"[ml] retrain ERROR: {e}", flush=True)
        await asyncio.sleep(ML_RETRAIN_INTERVAL_S)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _flow_listener, _honeypot, _sensor
    loop = asyncio.get_running_loop()
    _arrancar_listener(loop)
    _flow_listener = _arrancar_flow_listener(loop)
    _honeypot = _arrancar_honeypot(loop)
    if SENSOR_ENABLED:
        _sensor = _arrancar_sensor(loop)
    retrain_task = asyncio.create_task(_ml_retrain_loop())
    yield
    retrain_task.cancel()
    if _flow_listener is not None:
        _flow_listener.stop()
    if _honeypot is not None:
        _honeypot.stop()
    if _sensor is not None:
        _sensor.stop()


app = FastAPI(title="Q-Sentinel", version="1.4.0", lifespan=lifespan)


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "version": "1.4.0"}


@app.get("/api/history")
async def get_history(
    since: Optional[float] = None,
    limit: int = 200,
    anomaly_only: bool = False,
) -> JSONResponse:
    """Histórico de eventos persistidos en SQLite.

    * `since`         — Unix epoch seconds. Solo eventos con `received_at >= since`.
    * `limit`         — máximo a devolver (default 200, hard cap 5000).
    * `anomaly_only`  — si true, solo `is_anomaly=1`.
    """
    capped = max(1, min(int(limit), 5000))
    try:
        rows = storage.query_events(since=since, limit=capped, anomaly_only=anomaly_only)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"count": len(rows), "events": rows})


@app.get("/api/timeseries")
async def get_timeseries(
    since: Optional[float] = None,
    bucket: int = 60,
) -> JSONResponse:
    """Timeseries agregada por bucket — feed para el chart del dashboard.

    Por defecto buckets de 60s (1 punto por minuto). Cada bucket trae
    avg/max/min de entropía y conteos total/anomalía.
    """
    capped_bucket = max(1, min(int(bucket), 3600))
    try:
        rows = storage.query_timeseries(since=since, bucket_seconds=capped_bucket)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"bucket_seconds": capped_bucket, "points": rows})


@app.get("/api/flows")
async def get_flows(
    since: Optional[float] = None,
    limit: int = 200,
    protocol: Optional[int] = None,
) -> JSONResponse:
    """Histórico de flujos NetFlow persistidos.

    * `since`     — Unix epoch seconds.
    * `limit`     — máximo a devolver (default 200, hard cap 5000).
    * `protocol`  — filtro por número IANA (1=icmp, 6=tcp, 17=udp).
    """
    capped = max(1, min(int(limit), 5000))
    try:
        rows = storage.query_flows(since=since, limit=capped, protocol_num=protocol)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    extra: dict = {}
    if _flow_listener is not None:
        extra["listener_stats"] = _flow_listener.stats()
    return JSONResponse({"count": len(rows), "flows": rows, **extra})


@app.get("/api/isolation-history")
async def get_isolation_history(since: Optional[float] = None, limit: int = 100) -> JSONResponse:
    """Histórico de acciones manuales aislar/reactivar — auditoría."""
    capped = max(1, min(int(limit), 1000))
    try:
        rows = storage.query_isolation_log(since=since, limit=capped)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"count": len(rows), "actions": rows})


@app.get("/api/topology")
async def get_topology() -> JSONResponse:
    """Devuelve el modelo lógico de la red para el renderer 3D.

    503 si `topology.yaml` no se pudo cargar al startup.
    """
    if _topology is None:
        return JSONResponse(
            {"error": "topology not loaded", "detail": _topology_error},
            status_code=503,
        )
    return JSONResponse(_topology.to_dict())


@app.get("/api/ml")
async def ml_status() -> dict:
    """Estado de la capa ML: modelos cargados, línea base local, contadores."""
    return detector.stats()


@app.post("/api/ml/retrain")
async def ml_retrain() -> JSONResponse:
    """Fuerza el re-entrenamiento de la línea base local desde SQLite.

    Pensado para validación/demos: evita reiniciar el servidor cada vez que
    se acumula tráfico nuevo. En producción el re-entrenamiento periódico
    (cada ML_RETRAIN_INTERVAL_S) basta.
    """
    ready = await asyncio.to_thread(detector.retrain_local, storage)
    return JSONResponse({"ready": ready, "local": detector.local.stats()})


@app.get("/api/honeypot")
async def honeypot_status() -> JSONResponse:
    """Estado del honeypot: si está activo, sus señuelos y cuántos hits lleva."""
    hp = _honeypot
    running = hp is not None and hp.is_running()
    base = hp.stats() if hp is not None else {
        "hits": 0, "errors": 0, "puertos": list(DEFAULT_DECOYS)}
    # Nombre de servicio por puerto, para mostrarlo en la UI.
    servicios = {p: DEFAULT_DECOYS[p][0] for p in DEFAULT_DECOYS}
    return JSONResponse({"running": running, "servicios": servicios, **base})


@app.post("/api/honeypot/toggle")
async def honeypot_toggle() -> JSONResponse:
    """Activa o desactiva el honeypot (levanta o cierra los señuelos)."""
    global _honeypot
    if _honeypot is not None and _honeypot.is_running():
        _honeypot.stop()
        _honeypot = None
        return JSONResponse({"running": False})
    _honeypot = _arrancar_honeypot(asyncio.get_running_loop())
    return JSONResponse({"running": True, **_honeypot.stats()})


@app.post("/api/honeypot/test")
async def honeypot_test() -> JSONResponse:
    """Genera un hit REAL conectándose a un señuelo propio — para demostrar la
    reacción del sistema de punta a punta (evento anómalo + KPIs + Anomalías)."""
    if _honeypot is None or not _honeypot.is_running():
        return JSONResponse({"error": "el honeypot está apagado; actívalo primero"},
                            status_code=400)
    port = next(iter(DEFAULT_DECOYS))

    def _tocar() -> None:
        import socket as _sock
        c = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        c.settimeout(2.0)
        try:
            c.connect(("127.0.0.1", port))
            try:
                c.recv(64)            # recibe el banner falso
            except Exception:
                pass
            c.sendall(b"intento-de-intrusion-de-prueba\r\n")
        finally:
            c.close()

    await asyncio.to_thread(_tocar)
    return JSONResponse({"ok": True, "port": port,
                         "service": DEFAULT_DECOYS[port][0]})


@app.get("/api/soar")
async def soar_status() -> JSONResponse:
    """Estado del SOAR: modo, si tiene privilegios, IPs activas, lista blanca."""
    return JSONResponse(soar.stats())


@app.post("/api/soar/mode")
async def soar_set_mode(req: dict) -> JSONResponse:
    """Cambia el modo de respuesta: 'manual' (operador decide) o 'auto'."""
    try:
        mode = soar.set_mode((req or {}).get("mode"))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"mode": mode, **soar.stats()})


@app.get("/api/soar/blocked")
async def soar_blocked(active_only: bool = False) -> JSONResponse:
    """Lista de IPs bloqueadas (o intentos), más recientes primero."""
    return JSONResponse({"blocked": soar.list_blocked(active_only=active_only)})


@app.post("/api/block")
async def soar_block(req: dict) -> JSONResponse:
    """Bloqueo MANUAL de una IP por el operador (respeta la lista blanca).

    Emite además un SentinelEvent para que la acción aparezca en Anomalías y
    suba al KPI de «IPs bloqueadas», igual que un bloqueo automático.
    """
    ip = (req or {}).get("ip")
    if not ip:
        return JSONResponse({"error": "ip requerida"}, status_code=400)
    reason = (req or {}).get("reason") or "bloqueo manual"
    rec = await asyncio.to_thread(soar.block, ip, reason, "manual")

    if rec.get("ok"):
        from datetime import datetime
        ev = SentinelEvent(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            raw_message=f"<SOAR> BLOQUEO MANUAL de {ip} ({reason})",
            source_ip=ip,
            entropy=0.0,
            sha3=hash_sha3(f"block:{ip}:{rec.get('ts')}"),
            is_trusted=False,
            is_anomaly=False,
            attacker_ip=ip,
            plan="A",
            blocked=True,
            response_log=[f"[soar] bloqueo manual de {ip} aplicado en el firewall",
                          f"  $ {rec.get('command', '')}"],
        )
        await _persist_record_and_broadcast(ev.to_dict())

    return JSONResponse(rec, status_code=200 if rec.get("ok")
                        else (400 if rec.get("skipped") else 502))


@app.post("/api/unblock")
async def soar_unblock(req: dict) -> JSONResponse:
    """Retira el bloqueo de una IP del firewall local."""
    ip = (req or {}).get("ip")
    if not ip:
        return JSONResponse({"error": "ip requerida"}, status_code=400)
    rec = await asyncio.to_thread(soar.unblock, ip)
    return JSONResponse(rec, status_code=200 if rec.get("ok") else 502)


@app.get("/api/discovery")
async def discovery(window: Optional[float] = None, min_flows: int = 2,
                    group_external: bool = True) -> JSONResponse:
    """Topología DESCUBIERTA automáticamente a partir de los flujos observados.

    A diferencia de `/api/topology` (modelo declarado a mano en topology.yaml),
    este endpoint construye el grafo de red observando el tráfico: nodos, roles
    inferidos, servicios expuestos y relaciones. Si existe topology.yaml, se usa
    solo como capa de anotación (etiquetas, criticidad) sobre lo descubierto.

    * `window`     — segundos hacia atrás a considerar (None = todo el histórico).
    * `min_flows`  — descarta nodos con menos flujos (doma el ruido efímero).
    """
    from core.discovery import (discover_from_storage, annotate, filter_graph,
                                 collapse_external, drop_noise)
    from core.identify import enrich_graph

    def _build() -> dict:
        graph = discover_from_storage(storage, window_s=window)
        if _topology is not None:
            annotate(graph, _topology)
        graph = drop_noise(graph)  # quita broadcast/multicast antes de agrupar
        if group_external:
            graph = collapse_external(graph)  # externos -> nodo «Internet»
        graph = filter_graph(graph, max(1, int(min_flows)))
        enrich_graph(graph, storage)  # nombre + fabricante por IP (Fase O)
        return graph

    try:
        graph = await asyncio.to_thread(_build)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse(graph)


@app.get("/api/stats")
async def stats() -> dict:
    return {
        "total_eventos": manager.total_eventos,
        "total_anomalias": manager.total_anomalias,
        "ips_bloqueadas": manager.ips_bloqueadas,
        "clientes_conectados": len(manager.active),
    }


@app.post("/api/test-event")
async def test_event() -> JSONResponse:
    """Inyecta un evento sintético — útil para verificar el WS sin lab."""
    from datetime import datetime

    fake = SentinelEvent(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        raw_message="<188>SYNTHETIC: SEC-6-IPACCESSLOGP from 10.0.0.99",
        source_ip="127.0.0.1",
        entropy=5.42,
        sha3="a" * 64,
        is_trusted=False,
        is_anomaly=True,
        attacker_ip="10.0.0.99",
        plan="A",
        blocked=True,
        response_log=["[!] synthetic test event"],
    )
    await _persist_record_and_broadcast(fake.to_dict())
    return JSONResponse({"injected": True})


@app.post("/api/test-flow")
async def test_flow(req: dict | None = None) -> JSONResponse:
    """Inyecta un flujo sintético — verifica partículas y veredicto ML sin lab.

    Body opcional: {"anomalous": true} fabrica un flujo tipo exfiltración y
    además fuerza `ml.is_anomaly` (es debug visual, no validación del
    detector: para eso está el lab). Sin body, fabrica tráfico web normal.
    """
    anomalous = bool((req or {}).get("anomalous"))
    flow = {
        "src_ip": "10.10.1.10", "dst_ip": "10.0.0.99",
        "src_port": 51234, "dst_port": 4444 if anomalous else 443,
        "protocol_num": 6, "protocol": "tcp",
        "packets": 40000 if anomalous else 38,
        "bytes": 50_000_000 if anomalous else 24_000,
        "duration_ms": 60_000 if anomalous else 1_800,
        "exporter": "127.0.0.1",
        "src_node": "dept-ti", "dst_node": "external",
    }
    flow["ml"] = detector.evaluate(flow)
    if anomalous:
        flow["ml"]["is_anomaly"] = True
        if "debug" not in flow["ml"]["detectors"]:
            flow["ml"]["detectors"].append("debug")
    await manager.broadcast({"kind": "flow", "payload": flow})
    return JSONResponse({"injected": True, "ml": flow["ml"]})


async def _persist_record_and_broadcast(payload: dict) -> None:
    """Punto único para emitir un SentinelEvent: persiste, contabiliza, broadcastea.

    Lo usan tanto `/api/test-event` como `_broadcast_responder_log`. El
    listener real tiene su propia copia inline porque corre desde un
    thread sync y necesita `run_coroutine_threadsafe`.
    """
    try:
        storage.save_event(payload)
    except Exception as e:
        print(f"[storage] save_event ERROR: {e}", flush=True)
    manager.record_event(payload)
    await manager.broadcast({"kind": "event", "payload": payload})


# --- Aislamiento de segmentos (Fase G: touch-to-isolate) ---

# Tipos de nodo que pueden ser aislados desde la UI. El resto (router,
# switch, sentinel, host individual) se rechaza en `/api/isolate`.
ISOLATABLE_TYPES = {"department", "external"}


def _resolve_isolatable(node_id: str):
    """Devuelve `(node, error_response)` — uno y solo uno será None."""
    if _topology is None:
        return None, JSONResponse(
            {"error": "topology not loaded", "detail": _topology_error},
            status_code=503,
        )
    node = _topology.node(node_id)
    if not node:
        return None, JSONResponse({"error": f"node {node_id!r} no existe"}, status_code=404)
    if node.type.value not in ISOLATABLE_TYPES:
        return None, JSONResponse(
            {"error": f"nodo de tipo {node.type.value!r} no es aislable",
             "isolatable_types": sorted(ISOLATABLE_TYPES)},
            status_code=400,
        )
    if not node.interface:
        return None, JSONResponse(
            {"error": f"nodo {node_id!r} no tiene interfaz declarada en topology.yaml"},
            status_code=400,
        )
    return node, None


@app.get("/api/isolated")
async def get_isolated() -> dict:
    """Lista los node_ids aislados actualmente."""
    return {"isolated": sorted(manager.isolated_segments)}


@app.post("/api/isolate")
async def isolate(req: dict) -> JSONResponse:
    """Aplica `shutdown` al subif del nodo y marca el segmento como aislado."""
    node_id = (req or {}).get("node_id")
    if not node_id:
        return JSONResponse({"error": "node_id requerido"}, status_code=400)

    node, err = _resolve_isolatable(node_id)
    if err:
        return err

    log_lines: List[str] = []
    from core.responder import aislar_segmento
    ok = aislar_segmento(node.label, node.interface, on_log=log_lines.append)

    # Auditamos siempre — incluso intentos fallidos quedan en la DB
    # para forensia posterior.
    try:
        storage.save_isolation(node_id, node.interface, "isolate", ok, log_lines)
    except Exception as e:
        print(f"[storage] save_isolation ERROR: {e}", flush=True)

    if ok:
        manager.isolated_segments.add(node_id)
        await manager.broadcast({
            "kind": "topology_state",
            "payload": {"isolated": sorted(manager.isolated_segments)},
        })
        # También enviamos los comandos SSH como un "evento" sintético para
        # que aparezcan en el panel de consola SSH del dashboard.
        await _broadcast_responder_log(
            f"AISLAMIENTO MANUAL: {node.label}",
            node.label,
            log_lines,
        )

    return JSONResponse(
        {"success": ok, "node_id": node_id, "interface": node.interface, "log": log_lines},
        status_code=200 if ok else 502,
    )


@app.post("/api/unisolate")
async def unisolate(req: dict) -> JSONResponse:
    """Reverso de `/api/isolate` — `no shutdown` del subif."""
    node_id = (req or {}).get("node_id")
    if not node_id:
        return JSONResponse({"error": "node_id requerido"}, status_code=400)

    node, err = _resolve_isolatable(node_id)
    if err:
        return err

    log_lines: List[str] = []
    from core.responder import reactivar_segmento
    ok = reactivar_segmento(node.label, node.interface, on_log=log_lines.append)

    try:
        storage.save_isolation(node_id, node.interface, "unisolate", ok, log_lines)
    except Exception as e:
        print(f"[storage] save_isolation ERROR: {e}", flush=True)

    if ok:
        manager.isolated_segments.discard(node_id)
        await manager.broadcast({
            "kind": "topology_state",
            "payload": {"isolated": sorted(manager.isolated_segments)},
        })
        await _broadcast_responder_log(
            f"REACTIVACION MANUAL: {node.label}",
            node.label,
            log_lines,
        )

    return JSONResponse(
        {"success": ok, "node_id": node_id, "interface": node.interface, "log": log_lines},
        status_code=200 if ok else 502,
    )


async def _broadcast_responder_log(title: str, label: str, log_lines: List[str]) -> None:
    """Empaqueta los comandos SSH ejecutados como un SentinelEvent sintético.

    De esta forma el panel "Consola SSH" del dashboard refleja también
    las acciones manuales del operador, no solo las automáticas.
    """
    from datetime import datetime

    fake = SentinelEvent(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        raw_message=f"<MANUAL> {title}",
        source_ip="127.0.0.1",
        entropy=0.0,
        sha3="m" * 64,
        is_trusted=True,
        is_anomaly=False,
        attacker_ip=None,
        plan="NONE",
        blocked=False,
        response_log=log_lines,
    )
    await _persist_record_and_broadcast(fake.to_dict())


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    print(
        f"[server] cliente WS conectado ({len(manager.active)} activo/s)",
        flush=True,
    )
    try:
        while True:
            # Drenamos los mensajes del cliente para mantener la conexión
            # viva; el protocolo es de un solo sentido (server → cliente).
            await ws.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(ws)
        print(
            f"[server] cliente WS desconectado ({len(manager.active)} activo/s)",
            flush=True,
        )


# Servimos el frontend estático desde el mismo proceso. El mount va
# DESPUÉS de los endpoints API/WS porque mount("/") es greedy.
WEB_DIR = Path(__file__).parent / "web"
WEB_DIR.mkdir(exist_ok=True)
app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
