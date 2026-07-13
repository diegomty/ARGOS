// Vista "Flujos": tabla en vivo del tráfico NetFlow.
//
// Al mostrarse, carga el histórico reciente desde /api/flows. Los flujos
// nuevos llegan en tiempo real por el evento `qs:flow` que reemite main.js
// desde el WebSocket, y se anteponen a la tabla. Cada fila muestra el
// veredicto del detector ML híbrido cuando está disponible (los flujos en
// vivo lo traen; los históricos de la base no lo tienen persistido).

const tbody = document.getElementById('flujos-body');
const statusEl = document.getElementById('flujos-status');
const emptyEl = document.getElementById('flujos-empty');

const MAX_ROWS = 300;
let flows = [];               // más reciente primero
let loaded = false, lastFetch = 0, active = false;

// Mapa mínimo puerto -> servicio para etiquetar la columna.
const PORTS = {
  20: 'ftp', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
  80: 'http', 110: 'pop3', 139: 'netbios', 143: 'imap', 389: 'ldap',
  443: 'https', 445: 'smb', 587: 'smtp', 993: 'imaps', 995: 'pop3s',
  1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
  8080: 'http', 8443: 'https',
};

function fmtBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}
function fmtDur(ms) { return ms >= 1000 ? (ms / 1000).toFixed(1) + ' s' : (ms | 0) + ' ms'; }
function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString('es', { hour12: false })
    + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
function esc(s) { return String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function svc(f) { return (PORTS[f.dst_port] || f.protocol || '?') + ' :' + f.dst_port; }

function rowHtml(f) {
  const t = f.received_at ? f.received_at * 1000 : (f._t || Date.now());
  const anom = f.ml && f.ml.is_anomaly;
  let ml = '<span class="badge-ok">—</span>';
  if (f.ml) {
    ml = anom
      ? `<span class="badge-anom">${esc(f.ml.detectors.join(', ') || 'anómalo')}</span>`
      : '<span class="badge-ok">ok</span>';
  }
  return `<tr class="${anom ? 'flow-anom' : ''}">`
    + `<td class="mono muted">${fmtTime(t)}</td>`
    + `<td class="mono">${esc(f.src_ip)}:${f.src_port}</td>`
    + `<td class="mono">${esc(f.dst_ip)}</td>`
    + `<td>${esc(svc(f))}</td>`
    + `<td class="num">${f.packets}</td>`
    + `<td class="num">${fmtBytes(f.bytes)}</td>`
    + `<td class="num muted">${fmtDur(f.duration_ms || 0)}</td>`
    + `<td>${ml}</td></tr>`;
}

function updateStatus() {
  const anom = flows.reduce((s, f) => s + (f.ml && f.ml.is_anomaly ? 1 : 0), 0);
  statusEl.textContent = `${flows.length} flujos · ${anom} anómalos`;
}

function render() {
  if (!flows.length) { emptyEl.style.display = 'flex'; tbody.innerHTML = ''; updateStatus(); return; }
  emptyEl.style.display = 'none';
  tbody.innerHTML = flows.map(rowHtml).join('');
  updateStatus();
}

async function load() {
  try {
    const j = await fetch('/api/flows?limit=200').then(r => r.json());
    flows = j.flows || [];
    loaded = true; lastFetch = Date.now();
    render();
  } catch (err) {
    statusEl.textContent = 'error cargando /api/flows';
  }
}

// Flujo en vivo (reemitido por main.js desde el WebSocket).
document.addEventListener('qs:flow', (e) => {
  const f = e.detail; f._t = Date.now();
  flows.unshift(f);
  if (flows.length > MAX_ROWS) flows.length = MAX_ROWS;
  if (active) {
    emptyEl.style.display = 'none';
    tbody.insertAdjacentHTML('afterbegin', rowHtml(f));
    while (tbody.children.length > MAX_ROWS) tbody.removeChild(tbody.lastChild);
    updateStatus();
  }
});

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'flujos';
  if (!active) return;
  if (!loaded || Date.now() - lastFetch > 8000) load();
  else render();
});
