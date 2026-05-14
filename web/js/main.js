import { state, ingest, tick } from './state.js';
import { MeshView } from './viewMesh.js';
import { pushTicker } from './ticker.js';
import { pushDashboard } from './dashboard.js';
import { showNodeModal } from './modal.js';
import { TimeseriesChart } from './chart.js';

// Tipos de nodo que el operador puede aislar desde el digital twin.
// (El backend rechaza el resto, pero filtramos también acá para no
// abrir el modal en nodos que no van a poder ejecutar la acción.)
const ISOLATABLE_TYPES = new Set(['department', 'external']);

// --- Vista 3D ---
const canvas = document.getElementById('canvas-mesh');
const view = new MeshView(canvas);

function resize() {
  const r = canvas.parentElement.getBoundingClientRect();
  view.resize(r.width, r.height);
}
window.addEventListener('resize', resize);
resize();

// --- Topología (carga única al arrancar) ---
fetch('/api/topology')
  .then(r => r.ok ? r.json() : Promise.reject(r.statusText))
  .then(topology => {
    view.setTopology(topology);
    console.info('[topology]', topology.name, topology.version,
      `${topology.nodes.length} nodos, ${topology.links.length} links`);
  })
  .catch(err => console.warn('[topology] no se pudo cargar:', err));

// --- Chart de timeseries (polling cada 5s + pulse en eventos) ---
const chart = new TimeseriesChart(document.getElementById('chart-container'));
chart.start();

// --- Render loop ---
let last = performance.now();
function loop(now) {
  const dt = Math.min((now - last) / 1000, 0.1);
  last = now;
  tick(dt);
  view.update(state, dt, now / 1000);
  view.render();
  requestAnimationFrame(loop);
}
requestAnimationFrame(loop);

// --- Stats DOM ---
const $total = document.getElementById('s-total');
const $anom  = document.getElementById('s-anom');
const $blocked = document.getElementById('s-blocked');
const $h = document.getElementById('s-h');
const $hStat = document.getElementById('stat-h');

function refreshStats() {
  $total.textContent = state.totalEvents;
  $anom.textContent = state.totalAnomalies;
  $blocked.textContent = state.blockedIps.size;
  $h.textContent = state.rawH.toFixed(2);
  $hStat.classList.toggle('alert', state.rawH > 5.0);
  $hStat.classList.toggle('warn',  state.rawH > 4.5 && state.rawH <= 5.0);
}

// --- Estado local de nodos aislados (sincronizado por WS) ---
const isolatedSet = new Set();

function applyTopologyState(payload) {
  isolatedSet.clear();
  for (const id of payload.isolated || []) isolatedSet.add(id);
  view.setIsolated([...isolatedSet]);
}

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
    } else if (msg.kind === 'topology_state') {
      applyTopologyState(msg.payload);
    } else if (msg.kind === 'flow') {
      view.spawnFlow(msg.payload);
    }
  };
}
connect();

// --- Botón de evento sintético (debug) ---
document.getElementById('btn-test').addEventListener('click', () => {
  fetch('/api/test-event', { method: 'POST' });
});

// --- Touch-to-isolate: click sobre un nodo abre el modal ---
//
// Distinguimos click de drag (OrbitControls) midiendo cuánto se movió
// el cursor entre mousedown y mouseup. Si el movimiento es < 5px, lo
// tratamos como un click de selección.

let pressPos = null;
const CLICK_THRESHOLD_PX = 5;

function onPress(x, y) { pressPos = { x, y }; }
function onRelease(x, y) {
  if (!pressPos) return;
  const dx = x - pressPos.x;
  const dy = y - pressPos.y;
  pressPos = null;
  if (Math.abs(dx) > CLICK_THRESHOLD_PX || Math.abs(dy) > CLICK_THRESHOLD_PX) return;

  const node = view.pickNode(x, y);
  if (!node) return;
  if (!ISOLATABLE_TYPES.has(node.type)) return;
  showNodeModal(node, isolatedSet.has(node.id));
}

canvas.addEventListener('mousedown', e => onPress(e.clientX, e.clientY));
canvas.addEventListener('mouseup',   e => onRelease(e.clientX, e.clientY));
canvas.addEventListener('touchstart', e => {
  if (e.touches[0]) onPress(e.touches[0].clientX, e.touches[0].clientY);
}, { passive: true });
canvas.addEventListener('touchend', e => {
  if (e.changedTouches[0]) onRelease(e.changedTouches[0].clientX, e.changedTouches[0].clientY);
});
