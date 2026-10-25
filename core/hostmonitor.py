"""Monitoreo ACTIVO de hosts (estilo Checkmk).

A diferencia del sensor pasivo (que escucha un segmento y necesita admin), aquí
el operador AGREGA hosts a mano por su IP y ARGOS los SONDEA:

  * ping periódico  -> estado UP/DOWN + latencia (RTT) + historial para graficar,
  * escaneo de puertos a demanda -> qué servicios responden.

Ventaja de usabilidad: el ping NO requiere privilegios de administrador y no
depende de elegir una interfaz — resuelve el "¿qué monitoreo?" para cualquier
usuario. Corre en un hilo daemon y guarda el historial en SQLite.
"""

from __future__ import annotations

import platform
import re
import socket
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional

_IS_WINDOWS = platform.system() == "Windows"

# Puertos comunes para el escaneo a demanda (servicio por puerto, para la UI).
COMMON_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 8000: "http-alt",
    8080: "http-alt", 8443: "https-alt",
}


def ping(ip: str, timeout: float = 1.0) -> tuple[bool, Optional[float]]:
    """Hace UN ping a `ip`. Devuelve (up, rtt_ms). Multiplataforma, sin admin."""
    if _IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        out = ((p.stdout or "") + (p.stderr or "")).lower()
    except Exception:
        return False, None
    # Una respuesta real trae "ttl=" (en ES e EN). "host de destino inaccesible"
    # / "destination host unreachable" no la trae -> correctamente DOWN.
    up = "ttl=" in out
    rtt = None
    # "time=1.2 ms" / "tiempo=1.2 ms" / "time<1ms" / "tiempo<1ms"
    m = re.search(r"(?:time|tiempo)[=<]\s*(\d+(?:[.,]\d+)?)", out)
    if m:
        try:
            rtt = float(m.group(1).replace(",", "."))
        except ValueError:
            rtt = None
    return up, rtt


def scan_ports(ip: str, ports: Optional[List[int]] = None,
               timeout: float = 0.6) -> List[Dict[str, Any]]:
    """Escaneo TCP-connect a demanda. Devuelve los puertos ABIERTOS con su servicio."""
    ports = ports or sorted(COMMON_PORTS)
    abiertos: List[Dict[str, Any]] = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, p)) == 0:
                abiertos.append({"port": p, "service": COMMON_PORTS.get(p, "?")})
        except Exception:
            pass
        finally:
            s.close()
    return abiertos


def _age_since_change(samples: List[Dict[str, Any]], current_up: Any, now: float) -> Optional[float]:
    """Segundos desde que el estado UP/DOWN cambió por última vez (muestras asc)."""
    if not samples or current_up is None:
        return None
    last_diff_ts = None
    for s in samples:
        if bool(s["up"]) != bool(current_up):
            last_diff_ts = s["ts"]
    return (now - last_diff_ts) if last_diff_ts else (now - samples[0]["ts"])


class HostMonitor:
    """Sondea periódicamente los hosts registrados y guarda su estado/historial."""

    def __init__(self, storage: Any, interval: float = 10.0) -> None:
        self.storage = storage
        self.interval = interval
        self._latest: Dict[str, Dict[str, Any]] = {}   # ip -> {up, rtt_ms, ts}
        self._ports: Dict[str, Dict[str, Any]] = {}     # ip -> {ts, open:[...]} (caché del último escaneo)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_prune = 0.0

    # ---- Ciclo de vida ----

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, daemon=True, name="host-monitor")
        self._thread.start()
        print("[hostmon] monitoreo activo de hosts arrancado", flush=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                hosts = [h for h in self.storage.list_monitored_hosts() if h.get("enabled", 1)]
                for h in hosts:
                    if self._stop.is_set():
                        break
                    self._probe(h["ip"])
                # Poda el historial una vez por hora.
                now = time.time()
                if now - self._last_prune > 3600:
                    self.storage.prune_host_samples()
                    self._last_prune = now
            except Exception as e:
                print(f"[hostmon] loop error: {e}", flush=True)
            self._stop.wait(self.interval)

    def _probe(self, ip: str) -> Dict[str, Any]:
        up, rtt = ping(ip)
        state = {"up": up, "rtt_ms": rtt, "ts": time.time()}
        with self._lock:
            self._latest[ip] = state
        try:
            self.storage.save_host_sample(ip, up, rtt)
        except Exception:
            pass
        return state

    # ---- API ----

    def add(self, ip: str, label: Optional[str] = None) -> Dict[str, Any]:
        self.storage.add_monitored_host(ip, label)
        return self._probe(ip)   # un sondeo inmediato para no esperar al ciclo

    def remove(self, ip: str) -> None:
        self.storage.remove_monitored_host(ip)
        with self._lock:
            self._latest.pop(ip, None)

    def list(self) -> List[Dict[str, Any]]:
        try:
            ids = self.storage.query_identities() or {}
        except Exception:
            ids = {}
        _k = {"OK": "ok", "WARN": "warn", "CRIT": "crit", "PEND": "pend", "UNKNOWN": "unknown"}
        out = []
        for h in self.storage.list_monitored_hosts():
            ip = h["ip"]
            with self._lock:
                st = self._latest.get(ip, {})
            sv = self.services(ip, identities=ids)
            counts = {"ok": 0, "warn": 0, "unknown": 0, "crit": 0, "pend": 0}
            for s in sv["services"]:
                key = _k.get(s["state"])
                if key:
                    counts[key] += 1
            out.append({**h, "up": st.get("up"), "rtt_ms": st.get("rtt_ms"),
                        "last_check": st.get("ts"), "counts": counts})
        return out

    def probe_now(self, ip: str) -> Dict[str, Any]:
        return self._probe(ip)

    def scan(self, ip: str) -> List[Dict[str, Any]]:
        """Escanea puertos y CACHEA el resultado (para la vista de servicios)."""
        abiertos = scan_ports(ip)
        self._ports[ip] = {"ts": time.time(), "open": abiertos}
        return abiertos

    def history(self, ip: str, since: Optional[float] = None,
                limit: int = 500) -> List[Dict[str, Any]]:
        return self.storage.query_host_samples(ip, since=since, limit=limit)

    def services(self, ip: str, identities: Optional[Dict] = None) -> Dict[str, Any]:
        """Checks del host (estilo Checkmk): PING, latencia, puertos, identidad.

        Cada 'servicio' trae estado (OK/WARN/CRIT/PEND), resumen, age (tiempo
        desde el último cambio de estado) y checked (hace cuánto se sondeó).
        """
        now = time.time()
        with self._lock:
            st = dict(self._latest.get(ip, {}))
        up, rtt, last = st.get("up"), st.get("rtt_ms"), st.get("ts")
        samples = self.storage.query_host_samples(ip, limit=200)
        total = len(samples)
        ups = sum(1 for s in samples if s["up"])
        avail = round(100 * ups / total, 1) if total else None
        age = _age_since_change(samples, up, now)
        checked = (now - last) if last else None
        svc: List[Dict[str, Any]] = []

        # PING / disponibilidad
        if up is None:
            svc.append({"service": "PING", "state": "PEND", "summary": "aún sin sondear",
                        "age": age, "checked": checked})
        elif up:
            svc.append({"service": "PING", "state": "OK",
                        "summary": f"UP · RTT {rtt if rtt is not None else '?'} ms · "
                                   f"disponibilidad {avail}% ({total} muestras)",
                        "age": age, "checked": checked})
        else:
            svc.append({"service": "PING", "state": "CRIT",
                        "summary": f"DOWN · disponibilidad {avail}% ({total} muestras)",
                        "age": age, "checked": checked})

        # Latencia (umbrales OK/WARN/CRIT)
        if up and rtt is not None:
            state = "OK" if rtt < 100 else ("WARN" if rtt < 500 else "CRIT")
            svc.append({"service": "Latencia", "state": state,
                        "summary": f"{rtt} ms (warn > 100 ms, crit > 500 ms)",
                        "age": age, "checked": checked})

        # Puertos (del último escaneo cacheado)
        pc = self._ports.get(ip)
        if pc is None:
            svc.append({"service": "Puertos", "state": "PEND",
                        "summary": "no escaneados — usa «Escanear puertos»",
                        "age": None, "checked": None})
        elif not pc["open"]:
            svc.append({"service": "Puertos", "state": "OK",
                        "summary": "ninguno de los puertos comunes está abierto",
                        "age": now - pc["ts"], "checked": now - pc["ts"]})
        else:
            for p in pc["open"]:
                svc.append({"service": f"Puerto {p['port']} ({p['service']})",
                            "state": "OK", "summary": "abierto",
                            "age": now - pc["ts"], "checked": now - pc["ts"]})

        # Identidad (si el host ya está en el inventario)
        try:
            ids = identities if identities is not None else (self.storage.query_identities() or {})
            info = ids.get(ip)
            if info:
                det = " · ".join(filter(None, [info.get("vendor"),
                                               info.get("hostname"),
                                               info.get("device_type")]))
                if det:
                    svc.append({"service": "Identidad", "state": "OK", "summary": det,
                                "age": None, "checked": checked})
        except Exception:
            pass

        return {"ip": ip, "up": up, "services": svc}
