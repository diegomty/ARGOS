// Vista "Inventario": tabla de activos de la red — qué hay, quién es cada uno
// y qué tan peligroso es. Se alimenta del MISMO análisis pasivo que el mapa
// (/api/discovery), así que trae fabricante (MAC), hostname (DHCP/mDNS), rol y
// servicios ya calculados. Respeta una ventana temporal propia (hora/día/…) y
// cruza con SOAR para marcar los dispositivos bloqueados.
//
// Es gestión de activos: responde "¿qué hay en mi red ahora y qué riesgo tiene?"

const bodyEl = document.getElementById('inv-body');
const emptyEl = document.getElementById('inv-empty');
const statusEl = document.getElementById('inv-status');
const windowSel = document.getElementById('inv-window');
const filterSel = document.getElementById('inv-filter');
const refreshBtn = document.getElementById('inv-refresh');

// Puertos de servicios sensibles: exponerlos eleva el riesgo a "medio".
const SENSITIVE = new Set([21, 22, 23, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017, 9200]);

let active = false;
let lastNodes = [];
let blocked = new Set();

function esc(s) { return String(s == null ? '' : s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function fmtAgo(ts) {
  if (!ts) return '—';
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 90) return 'hace un momento';
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  return `hace ${Math.round(s / 86400)} d`;
}

// Riesgo derivado de las señales que ya trae el nodo + estado de SOAR.
function riskOf(n) {
  if (blocked.has(n.ip)) return { level: 'alto', label: 'alto', blocked: true };
  if (n.is_scanner || n.is_scan_target) return { level: 'alto', label: 'alto' };
  const svc = n.services || [];
  if (svc.some(s => SENSITIVE.has(s.port))) return { level: 'medio', label: 'medio' };
  return { level: 'bajo', label: 'bajo' };
}

function passesFilter(n, f) {
  const hasSvc = (n.services || []).length > 0;
  if (f === 'servidores') return hasSvc;
  if (f === 'clientes') return !hasSvc;
  if (f === 'riesgo') { const r = riskOf(n); return r.level !== 'bajo'; }
  return true;
}

function render() {
  const f = filterSel.value;
  // Excluimos la nube «Internet» (no es un dispositivo) y el ruido ya filtrado.
  let rows = lastNodes.filter(n => n.id !== 'internet' && n.ip !== 'internet');
  rows = rows.filter(n => passesFilter(n, f));
  // Orden: primero mayor riesgo, luego más flujos.
  const rank = { alto: 0, medio: 1, bajo: 2 };
  rows.sort((a, b) => rank[riskOf(a).level] - rank[riskOf(b).level] || (b.flows || 0) - (a.flows || 0));

  bodyEl.innerHTML = rows.map(n => {
    const r = riskOf(n);
    const svcNames = (n.services || []).map(s => s.name).slice(0, 4).join(', ')
      + ((n.services || []).length > 4 ? '…' : '');
    const riskCell = `<span class="risk risk-${r.level}">${r.label}</span>`
      + (r.blocked ? '<span class="inv-blocked">⛔ bloqueado</span>' : '');
    return `<tr>`
      + `<td class="mono">${esc(n.ip)}</td>`
      + `<td>${esc(n.vendor || '—')}</td>`
      + `<td>${esc(n.hostname || n.device_name || '—')}</td>`
      + `<td class="mono muted">${esc(n.mac || '—')}</td>`
      + `<td>${esc(n.role || '—')}</td>`
      + `<td class="inv-svc">${svcNames ? esc(svcNames) : '<span class="muted">—</span>'}</td>`
      + `<td class="muted">${fmtAgo(n.last_seen)}</td>`
      + `<td>${riskCell}</td></tr>`;
  }).join('');

  emptyEl.style.display = rows.length ? 'none' : '';
  const alto = rows.filter(n => riskOf(n).level === 'alto').length;
  statusEl.textContent = `${rows.length} dispositivo(s)`
    + (alto ? ` · ${alto} con riesgo alto` : '') + ` · ${blocked.size} bloqueado(s)`;
}

async function load() {
  statusEl.textContent = 'inventariando…';
  emptyEl.textContent = 'Consultando la red…';
  try {
    const win = localStorage.getItem('qs_inv_window') ?? '86400';
    // Mismo umbral de ruido que el mapa, para inventariar los mismos dispositivos.
    const mf = localStorage.getItem('qs_min_flows') || '2';
    let url = `/api/discovery?min_flows=${encodeURIComponent(mf)}`;
    if (win && win !== '0') url += `&window=${encodeURIComponent(win)}`;
    const [g, sb] = await Promise.all([
      fetch(url).then(r => r.json()),
      fetch('/api/soar/blocked?active_only=true').then(r => r.json()).catch(() => ({ blocked: [] })),
    ]);
    lastNodes = g.nodes || [];
    blocked = new Set((sb.blocked || []).filter(b => b.active).map(b => b.ip));
    render();
  } catch (e) {
    statusEl.textContent = 'error al inventariar';
    emptyEl.textContent = 'No se pudo cargar el inventario: ' + e;
    emptyEl.style.display = '';
  }
}

if (windowSel) {
  const saved = localStorage.getItem('qs_inv_window');
  if (saved !== null) windowSel.value = saved;
  windowSel.addEventListener('change', () => {
    localStorage.setItem('qs_inv_window', windowSel.value);
    if (active) load();
  });
}
if (filterSel) filterSel.addEventListener('change', render);
if (refreshBtn) refreshBtn.addEventListener('click', load);

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'inventario';
  if (active) load();
});
