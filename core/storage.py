"""Persistencia SQLite para Q-Sentinel.

Diseño:
  * Una sola DB en `qsentinel.db` (raíz del proyecto).
  * Modo WAL para que lecturas y escrituras concurrentes no se bloqueen.
  * Un `threading.Lock` serializa las escrituras desde el listener thread
    y desde los handlers FastAPI — el rate de syslog es bajo (~10/s pico)
    así que la contención es despreciable.
  * Conexiones efímeras (open/close por operación) en vez de pool: simplifica
    el modelo de threading sin perder rendimiento a este volumen.

Tablas:
  * `events`           — un row por SentinelEvent
  * `isolation_log`    — un row por acción manual de aislamiento/reactivación
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_DB = Path(__file__).resolve().parent.parent / "qsentinel.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,    -- "YYYY-MM-DD HH:MM:SS.mmm" del listener
    received_at   REAL    NOT NULL,    -- Unix epoch (float, ms precision) — usado para queries
    raw_message   TEXT    NOT NULL,
    source_ip     TEXT    NOT NULL,
    entropy       REAL    NOT NULL,
    sha3          TEXT    NOT NULL,
    is_trusted    INTEGER NOT NULL,
    is_anomaly    INTEGER NOT NULL,
    attacker_ip   TEXT,
    plan          TEXT    NOT NULL,
    blocked       INTEGER NOT NULL,
    response_log  TEXT                 -- JSON array
);

CREATE INDEX IF NOT EXISTS idx_events_received   ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_anomaly_rt ON events(is_anomaly, received_at);

CREATE TABLE IF NOT EXISTS isolation_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    received_at   REAL    NOT NULL,
    node_id       TEXT    NOT NULL,
    interface     TEXT    NOT NULL,
    action        TEXT    NOT NULL,    -- 'isolate' | 'unisolate'
    success       INTEGER NOT NULL,
    response_log  TEXT
);
CREATE INDEX IF NOT EXISTS idx_iso_received ON isolation_log(received_at);

CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at   REAL    NOT NULL,
    exporter      TEXT    NOT NULL,    -- IP del router que exportó
    src_ip        TEXT    NOT NULL,
    dst_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL,
    dst_port      INTEGER NOT NULL,
    protocol_num  INTEGER NOT NULL,    -- IANA: 1=icmp, 6=tcp, 17=udp
    protocol      TEXT    NOT NULL,
    packets       INTEGER NOT NULL,
    bytes         INTEGER NOT NULL,
    duration_ms   INTEGER NOT NULL DEFAULT 0,  -- LAST_SWITCHED - FIRST_SWITCHED
    src_node      TEXT,                 -- node_id de la topología (NULL si IP no mapeada)
    dst_node      TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_received ON flows(received_at);
CREATE INDEX IF NOT EXISTS idx_flows_proto    ON flows(protocol_num, received_at);

CREATE TABLE IF NOT EXISTS identities (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    hostname    TEXT,                -- nombre observado (DHCP opción 12, mDNS, DNS inverso)
    vendor      TEXT,                -- fabricante inferido de la MAC (OUI)
    source      TEXT,                -- 'dhcp' | 'mdns' | 'dns' | 'arp'
    updated_at  REAL NOT NULL
);
"""


class Storage:
    """Punto único de acceso a la DB. Thread-safe."""

    def __init__(self, path: Path | str = DEFAULT_DB) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._init_schema()

    # ---- Internals ----

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; combinamos con BEGIN/COMMIT manuales si hace falta
        )
        conn.row_factory = sqlite3.Row
        # WAL: lecturas no bloquean escrituras y viceversa.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_schema(self) -> None:
        with self._lock, closing(self._connect()) as c:
            c.executescript(_SCHEMA)
            self._migrate(c)

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        """Migraciones aditivas para DBs creadas con schemas anteriores.

        `CREATE TABLE IF NOT EXISTS` no altera tablas existentes, así que
        las columnas nuevas se agregan acá con ALTER TABLE idempotente.
        """
        cols = {r["name"] for r in c.execute("PRAGMA table_info(flows)")}
        if "duration_ms" not in cols:
            c.execute("ALTER TABLE flows ADD COLUMN duration_ms INTEGER NOT NULL DEFAULT 0")

    # ---- Writes ----

    def save_event(self, payload: Dict[str, Any]) -> None:
        """Persiste un SentinelEvent serializado (`SentinelEvent.to_dict()`)."""
        row = (
            payload["timestamp"],
            time.time(),
            payload["raw_message"],
            payload["source_ip"],
            float(payload["entropy"]),
            payload["sha3"],
            int(bool(payload.get("is_trusted"))),
            int(bool(payload.get("is_anomaly"))),
            payload.get("attacker_ip"),
            payload.get("plan", "NONE"),
            int(bool(payload.get("blocked"))),
            json.dumps(payload.get("response_log") or [], ensure_ascii=False),
        )
        with self._lock, closing(self._connect()) as c:
            c.execute(
                """
                INSERT INTO events (
                  ts, received_at, raw_message, source_ip, entropy, sha3,
                  is_trusted, is_anomaly, attacker_ip, plan, blocked, response_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )

    def save_isolation(
        self,
        node_id: str,
        interface: str,
        action: str,
        success: bool,
        response_log: List[str],
    ) -> None:
        if action not in ("isolate", "unisolate"):
            raise ValueError(f"action inválido: {action!r}")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with self._lock, closing(self._connect()) as c:
            c.execute(
                """
                INSERT INTO isolation_log (
                  ts, received_at, node_id, interface, action, success, response_log
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    time.time(),
                    node_id,
                    interface,
                    action,
                    int(bool(success)),
                    json.dumps(response_log or [], ensure_ascii=False),
                ),
            )

    # ---- Reads ----

    def query_events(
        self,
        since: Optional[float] = None,
        limit: int = 200,
        anomaly_only: bool = False,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if since is not None:
            clauses.append("received_at >= ?")
            params.append(float(since))
        if anomaly_only:
            clauses.append("is_anomaly = 1")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(int(limit))

        sql = f"""
            SELECT id, ts, received_at, raw_message, source_ip, entropy, sha3,
                   is_trusted, is_anomaly, attacker_ip, plan, blocked, response_log
              FROM events
              {where}
             ORDER BY received_at DESC
             LIMIT ?
        """
        with self._lock, closing(self._connect()) as c:
            rows = c.execute(sql, params).fetchall()
            return [self._row_to_event(r) for r in rows]

    def query_timeseries(
        self,
        since: Optional[float] = None,
        bucket_seconds: int = 60,
    ) -> List[Dict[str, Any]]:
        """Buckets agregados de entropía. Útil para el chart de la UI."""
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds debe ser > 0")
        params: List[Any] = [bucket_seconds, bucket_seconds]
        where = ""
        if since is not None:
            where = "WHERE received_at >= ?"
            params.append(float(since))
        sql = f"""
            SELECT
                CAST(received_at / ? AS INTEGER) * ? AS bucket,
                COUNT(*)               AS count,
                SUM(is_anomaly)        AS anomaly_count,
                AVG(entropy)           AS avg_h,
                MAX(entropy)           AS max_h,
                MIN(entropy)           AS min_h
              FROM events
              {where}
             GROUP BY bucket
             ORDER BY bucket ASC
        """
        with self._lock, closing(self._connect()) as c:
            rows = c.execute(sql, params).fetchall()
            return [
                {
                    "ts": float(r["bucket"]),
                    "count": int(r["count"]),
                    "anomaly_count": int(r["anomaly_count"] or 0),
                    "avg_h": float(r["avg_h"]),
                    "max_h": float(r["max_h"]),
                    "min_h": float(r["min_h"]),
                }
                for r in rows
            ]

    def save_flow(self, flow: Dict[str, Any]) -> None:
        """Persiste un flujo NetFlow ya enriquecido con src_node/dst_node."""
        with self._lock, closing(self._connect()) as c:
            c.execute(
                """
                INSERT INTO flows (
                  received_at, exporter, src_ip, dst_ip, src_port, dst_port,
                  protocol_num, protocol, packets, bytes, duration_ms, src_node, dst_node
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    flow.get("exporter") or "",
                    flow["src_ip"],
                    flow["dst_ip"],
                    int(flow.get("src_port", 0) or 0),
                    int(flow.get("dst_port", 0) or 0),
                    int(flow.get("protocol_num", 0) or 0),
                    flow.get("protocol", "unknown"),
                    int(flow.get("packets", 0) or 0),
                    int(flow.get("bytes", 0) or 0),
                    int(flow.get("duration_ms", 0) or 0),
                    flow.get("src_node"),
                    flow.get("dst_node"),
                ),
            )

    def query_flows(
        self,
        since: Optional[float] = None,
        limit: int = 200,
        protocol_num: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if since is not None:
            clauses.append("received_at >= ?")
            params.append(float(since))
        if protocol_num is not None:
            clauses.append("protocol_num = ?")
            params.append(int(protocol_num))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(int(limit))
        sql = f"""
            SELECT id, received_at, exporter, src_ip, dst_ip, src_port, dst_port,
                   protocol_num, protocol, packets, bytes, duration_ms, src_node, dst_node
              FROM flows
              {where}
             ORDER BY received_at DESC
             LIMIT ?
        """
        with self._lock, closing(self._connect()) as c:
            rows = c.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    # ---- Identidades de dispositivos (nombre/fabricante por IP) ----

    def upsert_identity(self, ip: str, mac: Optional[str] = None,
                        hostname: Optional[str] = None, vendor: Optional[str] = None,
                        source: Optional[str] = None) -> None:
        """Guarda/actualiza lo que sabemos de un dispositivo por su IP.

        Fusiona: un campo nuevo en NULL no borra el valor ya guardado (COALESCE),
        así que cada fuente (ARP, DNS, DHCP, mDNS) aporta lo suyo sin pisar al
        resto. Un valor no-nulo sí reemplaza al anterior (el dato más reciente).
        """
        with self._lock, closing(self._connect()) as c:
            c.execute(
                """
                INSERT INTO identities (ip, mac, hostname, vendor, source, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                  mac        = COALESCE(excluded.mac, identities.mac),
                  hostname   = COALESCE(excluded.hostname, identities.hostname),
                  vendor     = COALESCE(excluded.vendor, identities.vendor),
                  source     = COALESCE(excluded.source, identities.source),
                  updated_at = excluded.updated_at
                """,
                (ip, mac, hostname, vendor, source, time.time()),
            )

    def query_identities(self) -> Dict[str, Dict[str, Any]]:
        """Todas las identidades conocidas, indexadas por IP."""
        with self._lock, closing(self._connect()) as c:
            rows = c.execute(
                "SELECT ip, mac, hostname, vendor, source, updated_at FROM identities"
            ).fetchall()
            return {r["ip"]: dict(r) for r in rows}

    def query_isolation_log(self, since: Optional[float] = None, limit: int = 100) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if since is not None:
            clauses.append("received_at >= ?")
            params.append(float(since))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(int(limit))
        sql = f"""
            SELECT id, ts, received_at, node_id, interface, action, success, response_log
              FROM isolation_log
              {where}
             ORDER BY received_at DESC
             LIMIT ?
        """
        with self._lock, closing(self._connect()) as c:
            rows = c.execute(sql, params).fetchall()
            return [
                {
                    "id": r["id"],
                    "ts": r["ts"],
                    "received_at": r["received_at"],
                    "node_id": r["node_id"],
                    "interface": r["interface"],
                    "action": r["action"],
                    "success": bool(r["success"]),
                    "response_log": json.loads(r["response_log"] or "[]"),
                }
                for r in rows
            ]

    def stats(self) -> Dict[str, Any]:
        """Métricas agregadas para `/api/stats` post-restart."""
        with self._lock, closing(self._connect()) as c:
            row = c.execute(
                """
                SELECT
                  COUNT(*) AS total,
                  SUM(is_anomaly) AS anomalies,
                  SUM(blocked) AS blocked
                FROM events
                """
            ).fetchone()
            return {
                "total_events": int(row["total"] or 0),
                "total_anomalies": int(row["anomalies"] or 0),
                "total_blocked": int(row["blocked"] or 0),
            }

    # ---- Helpers ----

    @staticmethod
    def _row_to_event(r: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": r["id"],
            "timestamp": r["ts"],
            "received_at": r["received_at"],
            "raw_message": r["raw_message"],
            "source_ip": r["source_ip"],
            "entropy": r["entropy"],
            "sha3": r["sha3"],
            "is_trusted": bool(r["is_trusted"]),
            "is_anomaly": bool(r["is_anomaly"]),
            "attacker_ip": r["attacker_ip"],
            "plan": r["plan"],
            "blocked": bool(r["blocked"]),
            "response_log": json.loads(r["response_log"] or "[]"),
        }
