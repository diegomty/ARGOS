"""SOAR — Security Orchestration, Automation and Response.

Cierra el ciclo del NDR: cuando ocurre una detección de ALTA confianza (hit de
honeypot o flood/DoS), ARGOS puede bloquear la IP atacante en el firewall del
propio host donde corre. Es portable: detecta el SO y usa el comando nativo —
`netsh advfirewall` en Windows, `iptables` en Linux/Kali.

Dos modos de operación, elegidos por el operador:

  * "manual" (por defecto): las detecciones se muestran, pero NADA se bloquea
    solo. El operador decide qué IP bloquear (botón en la UI / `/api/block`).
    Ideal para monitorear en vivo y responder a mano.
  * "auto": las detecciones de alta confianza disparan el bloqueo por sí solas,
    sujeto SIEMPRE a la política de seguridad.

Política de seguridad (se aplica en AMBOS modos, también al bloqueo manual):

  * Lista blanca dura: nunca se bloquea localhost, la IP propia, el gateway, el
    DNS ni los rangos que el operador declare. Evita el "auto-suicidio de red"
    (bloquear el router = quedarse sin red).
  * Cooldown: no se re-ejecuta el mismo bloqueo dentro de una ventana corta.

Si el proceso no corre con privilegios (admin/root), el comando de firewall
falla; se registra el intento con `ok=False` y su salida, sin tumbar nada — así
es seguro probar el flujo de punta a punta antes de bloquear de verdad.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple

_IS_WINDOWS = platform.system() == "Windows"

# Prefijo de las reglas que crea ARGOS — así se identifican y se pueden borrar
# sin tocar otras reglas del firewall del host.
_RULE_PREFIX = "ARGOS-block-"


# --------------------------------------------------------------------------- #
# Utilidades de bajo nivel                                                    #
# --------------------------------------------------------------------------- #

def _run(cmd: List[str], timeout: float = 8.0) -> Tuple[bool, str]:
    """Ejecuta un comando y devuelve (ok, salida-combinada)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        return p.returncode == 0, out
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _is_privileged() -> bool:
    """True si el proceso puede tocar el firewall (admin en Windows, root en *nix)."""
    try:
        if _IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _own_ips() -> List[str]:
    """IPs locales del host — para no auto-bloquearse."""
    ips = {"127.0.0.1", "::1"}
    try:
        host = socket.gethostname()
        for res in socket.getaddrinfo(host, None):
            ips.add(res[4][0])
    except Exception:
        pass
    # Truco UDP: la IP con la que el host sale a internet (no envía nada).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ips)


def _default_gateways() -> List[str]:
    """Gateways por defecto (best-effort, multiplataforma). Nunca lanza."""
    gws: set[str] = set()
    if _IS_WINDOWS:
        ok, out = _run(["powershell", "-NoProfile", "-Command",
                        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0'"
                        " -ErrorAction SilentlyContinue).NextHop"])
        if ok:
            for line in out.splitlines():
                line = line.strip()
                if line and _looks_like_ip(line):
                    gws.add(line)
    else:
        ok, out = _run(["ip", "route", "show", "default"])
        if ok:
            for tok in out.split():
                if _looks_like_ip(tok):
                    gws.add(tok)
    return sorted(gws)


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Backend de firewall (portable)                                              #
# --------------------------------------------------------------------------- #

def _fw_block(ip: str) -> Tuple[bool, str, str]:
    """Bloquea `ip` en el firewall local. Devuelve (ok, comando, salida)."""
    if _IS_WINDOWS:
        name = f"{_RULE_PREFIX}{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={name}", "dir=in", "action=block", f"remoteip={ip}"]
        ok, out = _run(cmd)
        return ok, " ".join(cmd), out
    # Linux/Kali: caída de tráfico entrante Y reenviado (por si ARGOS rutea).
    cmds = [["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"]]
    ok_all, outs = True, []
    for c in cmds:
        ok, out = _run(c)
        ok_all = ok_all and ok
        outs.append(f"$ {' '.join(c)}\n{out}".rstrip())
    return ok_all, " ; ".join(" ".join(c) for c in cmds), "\n".join(outs)


def _fw_unblock(ip: str) -> Tuple[bool, str, str]:
    """Retira el bloqueo de `ip`. Devuelve (ok, comando, salida)."""
    if _IS_WINDOWS:
        name = f"{_RULE_PREFIX}{ip}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        ok, out = _run(cmd)
        return ok, " ".join(cmd), out
    cmds = [["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"]]
    ok_all, outs = True, []
    for c in cmds:
        ok, out = _run(c)
        ok_all = ok_all and ok
        outs.append(f"$ {' '.join(c)}\n{out}".rstrip())
    return ok_all, " ; ".join(" ".join(c) for c in cmds), "\n".join(outs)


# --------------------------------------------------------------------------- #
# Motor SOAR                                                                  #
# --------------------------------------------------------------------------- #

class SoarEngine:
    """Orquesta la política de respuesta y ejecuta los bloqueos.

    Thread-safe: lo llaman los callbacks del sensor/honeypot (thread daemon) y
    los endpoints HTTP (event loop). Todo lo mutable va bajo `self._lock`.
    """

    MODES = ("manual", "auto")

    def __init__(self, cooldown: float = 30.0) -> None:
        self.mode = "manual"                       # arranca en el modo seguro
        self.cooldown = cooldown
        self.privileged = _is_privileged()
        self._lock = threading.Lock()
        # ip -> {ts, reason, actor, ok, command, output, active}
        self._blocked: Dict[str, dict] = {}
        self._auto_blocks = 0                      # contadores para stats()
        self._manual_blocks = 0
        self._skipped = 0

        # --- Lista blanca dura ---
        self._allow_ips: set[str] = set(_own_ips()) | set(_default_gateways())
        self._allow_ips |= {"0.0.0.0", "255.255.255.255"}
        self._allow_nets: List[ipaddress._BaseNetwork] = []
        # El operador puede añadir IPs/CIDRs con SOAR_ALLOWLIST="10.0.0.1,192.168.1.0/24".
        for token in (os.getenv("SOAR_ALLOWLIST", "") or "").split(","):
            token = token.strip()
            if not token:
                continue
            try:
                if "/" in token:
                    self._allow_nets.append(ipaddress.ip_network(token, strict=False))
                else:
                    self._allow_ips.add(str(ipaddress.ip_address(token)))
            except ValueError:
                pass

        print(f"[soar] motor listo — modo={self.mode} privilegiado={self.privileged} "
              f"lista_blanca={sorted(self._allow_ips)}", flush=True)

    # ---- Configuración ----

    def set_mode(self, mode: str) -> str:
        """Cambia el modo de operación. Devuelve el modo resultante."""
        mode = (mode or "").strip().lower()
        if mode not in self.MODES:
            raise ValueError(f"modo inválido: {mode!r} (usa {self.MODES})")
        with self._lock:
            self.mode = mode
        print(f"[soar] modo -> {mode}", flush=True)
        return mode

    # ---- Política ----

    def is_blockable(self, ip: str) -> Tuple[bool, str]:
        """(bloqueable?, motivo). No muta estado — se puede llamar para la UI."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, "IP inválida"
        if ip in self._allow_ips:
            return False, "en lista blanca"
        if any(addr in net for net in self._allow_nets):
            return False, "en lista blanca (red)"
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
            return False, "IP de sistema (loopback/multicast/reservada)"
        return True, ""

    # ---- Acciones ----

    def block(self, ip: str, reason: str = "", actor: str = "manual") -> dict:
        """Bloquea `ip` aplicando la política. Devuelve el registro del intento."""
        blockable, why = self.is_blockable(ip)
        if not blockable:
            with self._lock:
                self._skipped += 1
            return {"ip": ip, "ok": False, "skipped": True, "reason": why,
                    "actor": actor, "ts": time.time()}

        now = time.time()
        with self._lock:
            prev = self._blocked.get(ip)
            if prev and prev.get("active") and (now - prev["ts"]) < self.cooldown:
                return {**prev, "ip": ip, "deduped": True}

        ok, command, output = _fw_block(ip)
        rec = {"ip": ip, "ok": ok, "active": ok, "reason": reason or "manual",
               "actor": actor, "command": command, "output": output, "ts": now}
        with self._lock:
            self._blocked[ip] = rec
            if ok:
                if actor == "auto":
                    self._auto_blocks += 1
                else:
                    self._manual_blocks += 1
        estado = "OK" if ok else "FALLÓ (¿sin privilegios?)"
        print(f"[soar] bloqueo {actor} de {ip} — {estado}", flush=True)
        return rec

    def unblock(self, ip: str) -> dict:
        """Retira el bloqueo de `ip` del firewall."""
        ok, command, output = _fw_unblock(ip)
        now = time.time()
        with self._lock:
            rec = self._blocked.get(ip, {"ip": ip})
            rec.update({"active": False, "ok": ok, "unblocked_ts": now,
                        "command": command, "output": output})
            self._blocked[ip] = rec
        print(f"[soar] desbloqueo de {ip} — {'OK' if ok else 'FALLÓ'}", flush=True)
        return {"ip": ip, "ok": ok, "command": command, "output": output, "ts": now}

    def on_detection(self, ip: str, reason: str, kind: str = "") -> dict:
        """Punto de entrada para el sensor/honeypot ante una amenaza.

        En modo "auto" intenta bloquear (según política). En modo "manual" solo
        deja constancia de que la IP es candidata — la decisión es del operador.
        Devuelve un dict con `action` para que el server arme el response_log.
        """
        if self.mode == "auto":
            rec = self.block(ip, reason=reason, actor="auto")
            if rec.get("skipped"):
                return {"action": "skipped", "blocked": False, "reason": rec["reason"], **rec}
            return {"action": "blocked" if rec.get("ok") else "block_failed",
                    "blocked": bool(rec.get("ok")), **rec}
        # Modo manual: no se toca el firewall.
        blockable, why = self.is_blockable(ip)
        return {"action": "surfaced", "blocked": False, "mode": "manual",
                "blockable": blockable, "reason": why or reason, "ip": ip}

    # ---- Estado ----

    def list_blocked(self, active_only: bool = False) -> List[dict]:
        with self._lock:
            vals = list(self._blocked.values())
        if active_only:
            vals = [v for v in vals if v.get("active")]
        return sorted(vals, key=lambda r: r.get("ts", 0), reverse=True)

    def stats(self) -> dict:
        with self._lock:
            active = [ip for ip, r in self._blocked.items() if r.get("active")]
            return {
                "mode": self.mode,
                "privileged": self.privileged,
                "platform": "windows" if _IS_WINDOWS else "linux",
                "cooldown_s": self.cooldown,
                "active_blocks": sorted(active),
                "active_count": len(active),
                "auto_blocks": self._auto_blocks,
                "manual_blocks": self._manual_blocks,
                "skipped": self._skipped,
                "allowlist": sorted(self._allow_ips)
                + [str(n) for n in self._allow_nets],
            }
