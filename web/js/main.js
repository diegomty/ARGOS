// Núcleo del dashboard: WebSocket + KPIs + paneles + gráfica + detector ML.
// (El gemelo 3D fue retirado; la vista de red ahora es el Mapa autodescubierto,
//  que vive en su propio módulo mapview.js.)

import { state, ingest } from './state.js';
import { pushTicker } from './ticker.js';
import { pushDashboard } from './dashboard.js';
import { TimeseriesChart } from './chart.js';

// --- Toggle maximizar/restaurar paneles del sidebar ---
const sidebar = document.querySelector('.sidebar');
if (sidebar) {
  sidebar.addEventListener('click', (e) => {
    const btn = e.target.closest('.panel-toggle');
    if (!btn) return;
    const panel = btn.closest('.panel');
    if (!panel) return;
    const willMaximize = !panel.classList.contains('maximized');
    sidebar.querySelectorAll('.panel.maximized').forEach(p => p.classList.remove('maximized'));
    sidebar.classList.toggle('has-maximized', willMaximize);
    if (willMaximize) panel.classList.add('maximized');
  });
}

// --- Gráfica de entropía (polling cada 5s) ---
const chart = new TimeseriesChart(document.getElementById('chart-container'));
chart.start();

// --- KPIs ---
const $total = document.getElementById('s-total');
const $anom = document.getElementById('s-anom');
const $blocked = document.getElementById('s-blocked');
const $h = document.getElementById('s-h');
const $hStat = document.getElementById('stat-h');

function refreshStats() {
  $total.textContent = state.totalEvents;
  $anom.textContent = state.totalAnomalies;
  $blocked.textContent = state.blockedIps.size;
  $h.textContent = state.rawH.toFixed(2);
  $hStat.classList.toggle('alert', state.rawH > 5.0);
  $hStat.classList.toggle('warn', state.rawH > 4.5 && state.rawH <= 5.0);
}

// --- Tarjeta "Detector ML" ---
const $ml = document.getElementById('s-ml');
const $mlState = document.getElementById('s-ml-state');
const $mlStat = document.getElementById('stat-ml');
let mlFlagged = 0;

function noteFlowVerdict(flow) {
  if (!flow.ml?.is_anomaly) return;
  mlFlagged++;
  $ml.textContent = mlFlagged;
  $mlStat.classList.add('alert');
}

async function refreshMlStatus() {
  try {
    const st = await fetch('/api/ml').then(r => r.json());
    mlFlagged = st.flagged;
    $ml.textContent = mlFlagged;
    $mlStat.classList.toggle('alert', mlFlagged > 0);

    const inherited = st.inherited_loaded;
    const local = st.local?.ready;
    if (inherited && local) {
      $mlState.textContent = 'heredado + local activos';
      $mlStat.classList.add('ok');
      $mlStat.classList.remove('warn');
    } else if (inherited) {
      const n = st.local?.train_size ?? 0;
      const min = st.local?.min_flows ?? 200;
      $mlState.textContent = `heredado activo · base local ${n}/${min}`;
      $mlStat.classList.add('warn');
    } else if (local) {
      $mlState.textContent = 'solo línea base local';
      $mlStat.classList.add('warn');
    } else {
      $mlState.textContent = 'sin modelos — corre ml.train';
      $mlStat.classList.add('alert');
    }
  } catch {
    $mlState.textContent = 'estado no disponible';
  }
}
refreshMlStatus();
setInterval(refreshMlStatus, 10_000);

// --- WebSocket con envelope `{kind, payload}` ---
const $status = document.getElementById('status');

function connect() {
  $status.textContent = 'conectando…';
  $status.className = 'badge warn';

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    $status.textContent = 'inmunidad activa';
    $status.className = 'badge ok';
  };
  ws.onclose = () => {
    $status.textContent = 'desconectado · reintentando';
    $status.className = 'badge alert';
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (msg.kind === 'event') {
      const ev = msg.payload;
      ingest(ev);
      pushTicker(ev);
      pushDashboard(ev);
      refreshStats();
    } else if (msg.kind === 'flow') {
      noteFlowVerdict(msg.payload);
    }
    // Reemite el mensaje como evento del DOM para que los módulos de la consola
    // (Mapa, Flujos, Anomalías…) se suscriban sin acoplarse a este archivo.
    document.dispatchEvent(new CustomEvent('qs:' + msg.kind, { detail: msg.payload }));
  };
}
connect();

// --- Botón de evento sintético (debug) ---
document.getElementById('btn-test').addEventListener('click', () => {
  fetch('/api/test-event', { method: 'POST' });
});
