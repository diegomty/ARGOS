// Vista "Anomalías": panel de seguridad que unifica todo lo marcado.
//
// Combina dos fuentes en una sola lista cronológica:
//   * Eventos anómalos por entropía (persisten en /api/history?anomaly_only)
//   * Flujos anómalos del detector ML híbrido (llegan en vivo por qs:flow;
//     el veredicto no se persiste, así que estos son de la sesión actual)
// La cabecera muestra el estado del detector (heredado + local) desde /api/ml.

const tbody = document.getElementById('anom-body');
const statusEl = document.getElementById('anom-status');
const emptyEl = document.getElementById('anom-empty');

const MAX = 300;
let items = [];               // más reciente primero
let loaded = false, lastFetch = 0, active = false;
let mlText = 'detector ML';

function fmtBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString('es', { hour12: false })
    + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
function esc(s) { return String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function eventItem(ev) {
  return {
    type: 'evento',
    t: ev.received_at ? ev.received_at * 1000 : Date.now(),
    src: ev.attacker_ip || ev.source_ip || '—',
    detail: `H=${Number(ev.entropy).toFixed(2)} · ${esc((ev.raw_message || '').slice(0, 64))}`,
    tag: ev.blocked ? `PLAN ${ev.plan} · bloqueado` : (ev.plan && ev.plan !== 'NONE' ? `PLAN ${ev.plan}` : '—'),
  };
}
function flowItem(f) {
  return {
    type: 'flujo',
    t: Date.now(),
    src: `${f.src_ip}:${f.src_port}`,
    detail: `→ ${esc(f.dst_ip)} :${f.dst_port} · ${fmtBytes(f.bytes)}`,
    tag: (f.ml.detectors || []).join(', ') || 'anómalo',
  };
}

function rowHtml(it) {
  return `<tr>`
    + `<td class="mono muted">${fmtTime(it.t)}</td>`
    + `<td><span class="badge-tipo ${it.type}">${it.type}</span></td>`
    + `<td class="mono">${esc(it.src)}</td>`
    + `<td>${it.detail}</td>`
    + `<td><span class="badge-anom">${esc(it.tag)}</span></td></tr>`;
}

function updateStatus() {
  const flows = items.reduce((s, i) => s + (i.type === 'flujo' ? 1 : 0), 0);
  const evs = items.length - flows;
  statusEl.textContent = `${items.length} anomalías (${flows} flujos · ${evs} eventos) · ${mlText}`;
}

function render() {
  if (!items.length) { emptyEl.style.display = 'flex'; tbody.innerHTML = ''; updateStatus(); return; }
  emptyEl.style.display = 'none';
  tbody.innerHTML = items.map(rowHtml).join('');
  updateStatus();
}

function add(it) {
  items.unshift(it);
  if (items.length > MAX) items.length = MAX;
  if (active) {
    emptyEl.style.display = 'none';
    tbody.insertAdjacentHTML('afterbegin', rowHtml(it));
    while (tbody.children.length > MAX) tbody.removeChild(tbody.lastChild);
    updateStatus();
  }
}

async function loadStatus() {
  try {
    const m = await fetch('/api/ml').then(r => r.json());
    const loc = m.local && m.local.ready
      ? 'local listo'
      : `local ${m.local ? m.local.train_size : 0}/${m.local ? m.local.min_flows : 200}`;
    mlText = `heredado ${m.inherited_loaded ? '✓' : '—'} · ${loc}`;
    updateStatus();
  } catch { /* ignora */ }
}

async function load() {
  try {
    const j = await fetch('/api/history?anomaly_only=true&limit=100').then(r => r.json());
    items = (j.events || []).map(eventItem);   // ya vienen más recientes primero
    loaded = true; lastFetch = Date.now();
    render();
    loadStatus();
  } catch (err) {
    statusEl.textContent = 'error cargando anomalías';
  }
}

// Fuentes en vivo (reemitidas por main.js desde el WebSocket).
document.addEventListener('qs:event', (e) => {
  if (e.detail && e.detail.is_anomaly) add(eventItem(e.detail));
});
document.addEventListener('qs:flow', (e) => {
  if (e.detail && e.detail.ml && e.detail.ml.is_anomaly) add(flowItem(e.detail));
});

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'anomalias';
  if (!active) return;
  if (!loaded || Date.now() - lastFetch > 8000) load();
  else { render(); loadStatus(); }
});
