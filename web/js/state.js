// Estado global compartido por las dos vistas 3D y el dashboard.
//
// La idea: el WS empuja `SentinelEvent`s discretos, pero el render loop
// quiere valores continuos. Mantenemos H suavizada (EMA), y "pulsos"
// que decaen exponencialmente para los efectos de anomalía / bloqueo.

export const state = {
  smoothedH: 3.0,
  rawH: 3.0,
  pulse: 0.0,        // 0..1 — sube en anomalías, decae rápido
  blockPulse: 0.0,   // 0..1 — sube cuando se aplica una ACL, decae lento
  totalEvents: 0,
  totalAnomalies: 0,
  blockedIps: new Set(),
  attackOrigin: { x: 0, y: 0, z: 1 },
  lastEvent: null,
};

export function ingest(ev) {
  state.rawH = ev.entropy;
  state.smoothedH += (ev.entropy - state.smoothedH) * 0.18;
  state.totalEvents++;
  if (ev.is_anomaly) {
    state.totalAnomalies++;
    state.pulse = 1.0;
  }
  if (ev.blocked && ev.attacker_ip) {
    state.blockedIps.add(ev.attacker_ip);
    state.blockPulse = 1.0;
    state.attackOrigin = ipToDirection(ev.attacker_ip);
  }
  state.lastEvent = ev;
}

export function tick(dt) {
  // pulse decae a ~5% en 1s, blockPulse decae más lento (~20% en 1s)
  state.pulse *= Math.pow(0.05, dt);
  state.blockPulse *= Math.pow(0.20, dt);
}

// Hash determinista djb2-style → coordenadas esféricas.
// Mismo IP siempre cae en el mismo punto de la esfera, lo que da
// continuidad visual cuando el mismo atacante reincide.
function ipToDirection(ip) {
  let h = 5381;
  for (let i = 0; i < ip.length; i++) {
    h = (h * 33) ^ ip.charCodeAt(i);
  }
  h = h >>> 0;
  const azimuth = ((h & 0xffff) / 0xffff) * Math.PI * 2;
  const polar = (((h >>> 16) & 0xffff) / 0xffff) * Math.PI;
  return {
    x: Math.sin(polar) * Math.cos(azimuth),
    y: Math.cos(polar),
    z: Math.sin(polar) * Math.sin(azimuth),
  };
}
