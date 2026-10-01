"""Respuesta autónoma: aplica ACLs en el Cisco vía SSH (Paramiko)."""

import time
from typing import List, Optional

import paramiko

from . import config


def bloquear_ip_en_router(ip_objetivo: str, on_log=None,
                          interface: Optional[str] = None) -> bool:
    """Aplica `deny ip host <ip>` en la BLACKLIST de la interfaz de bloqueo.

    Devuelve True si la sesión SSH terminó sin excepciones. `on_log` es un
    callback opcional para emitir cada línea de progreso (lo usa el dashboard
    para mostrar el log de respuesta autónoma en tiempo real). `interface`
    permite sobreescribir la interfaz donde se aplica la ACL (por defecto
    `config.INTERFAZ_BLOQUEO`).

    Construcción de la ACL — CRÍTICO para que el bloqueo funcione y no encierre
    al operador (aprendido a la mala en el lab):

      * `1 permit ip host <ARGOS> any`  → SALVAGUARDA: ARGOS siempre puede
        alcanzar/administrar el router. Va PRIMERO, así ninguna edición
        posterior puede dejar la interfaz en «deny-all» y cortarnos el SSH.
      * `<n> deny ip host <atacante> any` → el bloqueo. Va ANTES del permit
        general (una ACL se evalúa de arriba abajo; si el `permit any` queda
        arriba, los `deny` son código muerto — ese era el bug).
      * `65000 permit ip any any`        → catch-all SIEMPRE al final.

    Se limpia cualquier `permit ip any any` mal ubicado antes de re-anclarlo
    al fondo, de modo que la función es idempotente y segura aunque la ACL
    venga de un estado previo roto.
    """
    if not ip_objetivo:
        return False

    iface = interface or config.INTERFAZ_BLOQUEO
    log = on_log or (lambda _: None)
    log(f"[!] INICIANDO CONTRAMEDIDA: bloqueando {ip_objetivo}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    exito = False
    try:
        ssh.connect(
            config.IP_ROUTER_ADMIN,
            username=config.USER_ROUTER,
            password=config.PASS_ROUTER,
            look_for_keys=False,
            allow_agent=False,
        )

        # Cisco IOS exige una sesión interactiva: cada exec_command()
        # abre un canal nuevo y se pierde el modo `conf t`.
        shell = ssh.invoke_shell()
        time.sleep(0.5)
        shell.recv(65535)  # descarta banner

        comandos: List[str] = [
            "terminal length 0",
            "conf t",
            "ip access-list extended BLACKLIST",
            f"1 permit ip host {config.MI_PC_IP} any",  # salvaguarda anti-encierro (va 1º)
            "no permit ip any any",                      # limpia catch-all mal ubicado
            f"deny ip host {ip_objetivo} any",           # el bloqueo (queda sobre el catch-all)
            "65000 permit ip any any",                   # catch-all SIEMPRE al final
            f"interface {iface}",
            "ip access-group BLACKLIST in",
            "end",
            "write memory",
        ]
        for cmd in comandos:
            shell.send(cmd + "\n")
            log(f"  router# {cmd}")
            time.sleep(0.4)

        # Drenamos el buffer de salida (útil para auditoría y para
        # confirmar visualmente que IOS aceptó cada comando).
        salida = ""
        while shell.recv_ready():
            salida += shell.recv(65535).decode("utf-8", errors="ignore")

        log(f"[✓] ÉXITO: IP {ip_objetivo} neutralizada")
        exito = True
    except Exception as e:
        log(f"[X] ERROR EN RESPUESTA: {e}")
    finally:
        ssh.close()

    return exito


def desbloquear_ip_en_router(ip_objetivo: str, on_log=None) -> bool:
    """Reverso de `bloquear_ip_en_router`: quita el `deny ip host <ip>` de la
    BLACKLIST. La salvaguarda y el catch-all se conservan intactos.
    """
    if not ip_objetivo:
        return False
    log = on_log or (lambda _: None)
    log(f"[!] LEVANTANDO BLOQUEO de {ip_objetivo}")
    comandos = [
        "conf t",
        "ip access-list extended BLACKLIST",
        f"no deny ip host {ip_objetivo} any",
        "end",
        "write memory",
    ]
    ok = _ejecutar_comandos_router(comandos, log)
    if ok:
        log(f"[OK] {ip_objetivo} desbloqueado")
    return ok


def _ejecutar_comandos_router(comandos: List[str], on_log) -> bool:
    """Ejecuta una lista de comandos contra IOS vía invoke_shell.

    Compartido entre `bloquear_ip_en_router`, `aislar_segmento` y
    `reactivar_segmento` para no duplicar la lógica de SSH/shell.
    Devuelve True si la sesión SSH terminó sin excepciones.
    """
    log = on_log or (lambda _: None)
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ok = False
    try:
        ssh.connect(
            config.IP_ROUTER_ADMIN,
            username=config.USER_ROUTER,
            password=config.PASS_ROUTER,
            look_for_keys=False,
            allow_agent=False,
        )
        shell = ssh.invoke_shell()
        time.sleep(0.5)
        shell.recv(65535)

        for cmd in comandos:
            shell.send(cmd + "\n")
            log(f"  router# {cmd}")
            time.sleep(0.4)

        salida = ""
        while shell.recv_ready():
            salida += shell.recv(65535).decode("utf-8", errors="ignore")

        ok = True
    except Exception as e:
        log(f"[X] ERROR: {e}")
    finally:
        ssh.close()
    return ok


def aislar_segmento(label: str, interface: str, on_log=None) -> bool:
    """Apaga la subinterfaz Cisco que sirve a un segmento → aislamiento total.

    `label` es solo cosmético (para los logs). `interface` es el nombre
    del subif p.ej. "f1/0.20". Devuelve True si los comandos se enviaron.
    """
    log = on_log or (lambda _: None)
    if not interface:
        log("[X] segmento sin interfaz asociada")
        return False
    log(f"[!] AISLAMIENTO: cerrando segmento {label} ({interface})")

    comandos = [
        "terminal length 0",
        "conf t",
        f"interface {interface}",
        "shutdown",
        "end",
        "write memory",
    ]
    ok = _ejecutar_comandos_router(comandos, log)
    if ok:
        log(f"[OK] {label} aislado")
    return ok


def reactivar_segmento(label: str, interface: str, on_log=None) -> bool:
    """Vuelve a levantar la subinterfaz — reverso de `aislar_segmento`."""
    log = on_log or (lambda _: None)
    if not interface:
        log("[X] segmento sin interfaz asociada")
        return False
    log(f"[!] REACTIVACION: levantando segmento {label} ({interface})")

    comandos = [
        "terminal length 0",
        "conf t",
        f"interface {interface}",
        "no shutdown",
        "end",
        "write memory",
    ]
    ok = _ejecutar_comandos_router(comandos, log)
    if ok:
        log(f"[OK] {label} reactivado")
    return ok
