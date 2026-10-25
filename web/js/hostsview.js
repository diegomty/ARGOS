// Vista "Hosts" — navegación de dos niveles estilo Checkmk:
//   * Panel LISTA ("All hosts"): tabla resumen con State + conteos OK/Wa/Un/Cr/Pd.
//   * Panel DETALLE ("Services of host"): al clic en un host, sus checks
//     (PING/latencia/puertos/identidad) con auto-refresco cada 30 s + gráfica.
//
// Backend: /api/hosts (lista con counts), /api/hosts/{ip}/services, /ping,
//          /portscan, /history ; /api/block para la acción Bloquear.

const listPanel = document.getElementById('hosts-list-panel');
const detailPanel = document.getElementById('hosts-detail-panel');
const bodyEl = document.getElementById('hosts-body');
const emptyEl = document.getElementById('hosts-empty');
const statusEl = document.getElementById('hosts-status');
const msgEl = document.getElementById('hosts-msg');
const ipInput = document.getElementById('host-ip');
const labelInput = document.getElementById('host-label');
const addBtn = document.getElementById('host-add');

const detailTitle = document.getElementById('host-detail-title');
const detailMsgEl = document.getElementById('host-detail-msg');
const spinnerEl = document.getElementById('host-spinner');
const hostServicesEl = document.getElementById('host-services');
const chartEl = document.getElementById('host-chart');
const backBtn = document.getElementById('host-back');
let selectedLabel = '';

const SVG_NS = 'http://www.w3.org/2000/svg';
const REFRESH_MS = 30000;
let active = false, pollTimer = null, detailTimer = null, selectedIp = null;
let refreshAt = 0, tickTimer = null;

// Anillo de cuenta regresiva: se va vaciando hacia el próximo refresco, y al
// pasar el cursor muestra los segundos que faltan.
function tick() {
  const remMs = Math.max(0, refreshAt - Date.now());
  const rem = Math.ceil(remMs / 1000);
  spinnerEl.style.setProperty('--p', ((remMs / REFRESH_MS) * 100).toFixed(1) + '%');
  spinnerEl.title = `Esta página se actualizará en ${rem} segundo${rem === 1 ? '' : 's'}`;
}
function startCountdown() {
  if (tickTimer) clearInterval(tickTimer);
  tick();
  tickTimer = setInterval(tick, 200);
}
function stopCountdown() {
  if (tickTimer) { clearInterval(tickTimer); tickTimer = null; }
}

function esc(s) { return String(s == null ? '' : s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function cv(name, fb) { return (getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fb); }
function msg(t, ok = true) { msgEl.textContent = t; msgEl.className = 'config-msg ' + (ok ? 'ok' : 'err'); }
function dmsg(t) { detailMsgEl.textContent = t || ''; }

function fmtDur(s) {
  if (s == null) return '—';
  s = Math.round(s);
  if (s < 60) return s + 's';
  if (s < 3600) return Math.round(s / 60) + 'm';
  if (s < 86400) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + 'd';
}

const STATE_COLOR = { OK: '--green', WARN: '--amber', CRIT: '--red', PEND: '--muted', UNKNOWN: '--muted' };
function stateChip(st) {
  const c = `var(${STATE_COLOR[st] || '--muted'})`;
  return `<span class="svc-state" style="color:${c};border-color:${c}">${esc(st)}</span>`;
}
function stateBadge(up) {
  if (up === true) return '<span class="svc-state" style="color:var(--green);border-color:var(--green)">UP</span>';
  if (up === false) return '<span class="svc-state" style="color:var(--red);border-color:var(--red)">DOWN</span>';
  return '<span class="svc-state" style="color:var(--muted);border-color:var(--muted)">?</span>';
}
function countCell(n, colorVar) {
  if (!n) return '<td class="num muted">0</td>';
  return `<td class="num" style="color:var(${colorVar});font-weight:bold">${n}</td>`;
}

// ---------- Panel LISTA ----------
function render(hosts) {
  bodyEl.innerHTML = (hosts || []).map(h => {
    const c = h.counts || {};
    return `<tr data-ip="${esc(h.ip)}" data-label="${esc(h.label || '')}" style="cursor:pointer">`
      + `<td>${stateBadge(h.up)}</td>`
      + `<td><span class="mono">${esc(h.ip)}</span>${h.label ? ' · ' + esc(h.label) : ''}</td>`
      + countCell(c.ok, '--green') + countCell(c.warn, '--amber') + countCell(c.unknown, '--muted')
      + countCell(c.crit, '--red') + countCell(c.pend, '--muted')
      + `<td></td></tr>`;
  }).join('');
  emptyEl.style.display = (hosts && hosts.length) ? 'none' : '';
  const up = (hosts || []).filter(h => h.up === true).length;
  statusEl.textContent = `${(hosts || []).length} host(s) · ${up} UP`;
}

async function load() {
  try { render((await fetch('/api/hosts').then(r => r.json())).hosts); }
  catch { statusEl.textContent = 'error consultando hosts'; }
}

addBtn.addEventListener('click', async () => {
  const ip = (ipInput.value || '').trim();
  if (!ip) { msg('escribe una IP', false); return; }
  msg('agregando y sondeando…');
  try {
    const r = await fetch('/api/hosts', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, label: (labelInput.value || '').trim() || null }),
    }).then(r => r.json());
    if (r.error) { msg(r.error, false); return; }
    msg(`host ${ip} agregado (${r.up ? 'UP ' + (r.rtt_ms ?? '') + 'ms' : 'DOWN'})`);
    ipInput.value = ''; labelInput.value = ''; load();
  } catch { msg('error al agregar', false); }
});

// Clic en una fila -> abrir el detalle del host.
bodyEl.addEventListener('click', (e) => {
  const tr = e.target.closest('tr[data-ip]');
  if (tr) openDetail(tr.dataset.ip, tr.dataset.label);
});

// ---------- Panel DETALLE (Services of host) ----------
function showList() {
  if (detailTimer) { clearInterval(detailTimer); detailTimer = null; }
  stopCountdown();
  selectedIp = null;
  detailPanel.hidden = true; listPanel.hidden = false;
}

function openDetail(ip, label) {
  selectedIp = ip;
  selectedLabel = label || '';
  listPanel.hidden = true; detailPanel.hidden = false;
  detailTitle.textContent = 'Services of host · ' + ip + (label ? ' (' + label + ')' : '');
  dmsg('');
  refreshDetail();
  if (detailTimer) clearInterval(detailTimer);
  detailTimer = setInterval(refreshDetail, REFRESH_MS);   // auto-actualiza cada 30 s
  startCountdown();
}

function renderServices(services) {
  hostServicesEl.innerHTML = (services || []).map(s =>
    '<tr><td>' + stateChip(s.state) + '</td>'
    + '<td>' + esc(s.service) + '</td>'
    + '<td class="muted">' + esc(s.summary) + '</td>'
    + '<td class="muted mono">' + fmtDur(s.age) + '</td>'
    + '<td class="muted mono">' + fmtDur(s.checked) + '</td></tr>').join('');
}

async function refreshDetail() {
  const ip = selectedIp;
  if (!ip) return;
  refreshAt = Date.now() + REFRESH_MS;   // reinicia la cuenta regresiva del anillo
  try {
    const sv = await fetch(`/api/hosts/${encodeURIComponent(ip)}/services`).then(r => r.json());
    renderServices(sv.services || []);
    const h = await fetch(`/api/hosts/${encodeURIComponent(ip)}/history?limit=200`).then(r => r.json());
    drawLatency(h.samples || []);
  } catch { /* ignore */ }
}

backBtn.addEventListener('click', () => { showList(); load(); });

// ---------- Menús desplegables (Host ▾ / Export ▾) ----------
const menus = Array.from(document.querySelectorAll('#hosts-detail-panel .hmenu'));
function closeMenus(except) {
  menus.forEach(m => {
    if (m === except) return;
    m.classList.remove('open');
    m.querySelector('.hmenu-pop').hidden = true;
    m.querySelector('.hmenu-btn').setAttribute('aria-expanded', 'false');
  });
}
menus.forEach(m => {
  const btn = m.querySelector('.hmenu-btn');
  const pop = m.querySelector('.hmenu-pop');
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const willOpen = pop.hidden;
    closeMenus(m);
    pop.hidden = !willOpen;
    m.classList.toggle('open', willOpen);
    btn.setAttribute('aria-expanded', String(willOpen));
  });
  pop.addEventListener('click', (e) => {
    const item = e.target.closest('.hmenu-item');
    if (!item) return;
    closeMenus();
    runAction(item.dataset.action);
  });
});
document.addEventListener('click', () => closeMenus());
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenus(); });

// ---------- Acciones del host actual ----------
async function runAction(action) {
  if (!selectedIp) return;
  const ip = selectedIp;
  switch (action) {
    case 'ping':
      dmsg('ping…');
      try { const r = await fetch(`/api/hosts/${encodeURIComponent(ip)}/ping`, { method: 'POST' }).then(r => r.json()); dmsg(r.up ? 'UP · ' + (r.rtt_ms ?? '?') + ' ms' : 'DOWN'); refreshDetail(); }
      catch { dmsg('error'); }
      break;
    case 'scan':
      dmsg('escaneando puertos…');
      try { await fetch(`/api/hosts/${encodeURIComponent(ip)}/portscan`, { method: 'POST' }); dmsg('puertos escaneados'); refreshDetail(); }
      catch { dmsg('error al escanear'); }
      break;
    case 'refresh':
      dmsg('actualizando…'); refreshDetail(); startCountdown(); dmsg('');
      break;
    case 'map':
      document.querySelector('.rail-item[data-view="centinela"]')?.click();
      break;
    case 'inv':
      document.querySelector('.rail-item[data-view="inventario"]')?.click();
      break;
    case 'block':
      dmsg('bloqueando…');
      try {
        const r = await fetch('/api/block', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, reason: 'bloqueo manual (Hosts)' }),
        }).then(r => r.json());
        dmsg(r.ok ? 'IP bloqueada' : (r.skipped ? 'no se bloquea: ' + r.reason : 'no se pudo bloquear'));
      } catch { dmsg('error al bloquear'); }
      break;
    case 'unblock':
      dmsg('desbloqueando…');
      try {
        const r = await fetch('/api/unblock', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip }),
        }).then(r => r.json());
        dmsg(r.ok ? 'IP desbloqueada' : 'no se pudo desbloquear');
      } catch { dmsg('error al desbloquear'); }
      break;
    case 'del':
      await fetch('/api/hosts/' + encodeURIComponent(ip), { method: 'DELETE' });
      showList(); msg(`host ${ip} quitado`); load();
      break;
    case 'csv': exportHost('csv'); break;
    case 'json': exportHost('json'); break;
  }
}

// ---------- Export del host actual (CSV / JSON) ----------
function download(name, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  a.href = url; a.download = name.replace('{stamp}', stamp);
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
async function exportHost(fmt) {
  const ip = selectedIp;
  if (!ip) return;
  dmsg(`exportando ${fmt.toUpperCase()}…`);
  const safe = ip.replace(/[^\w.-]/g, '_');
  try {
    const [sv, hist] = await Promise.all([
      fetch(`/api/hosts/${encodeURIComponent(ip)}/services`).then(r => r.json()),
      fetch(`/api/hosts/${encodeURIComponent(ip)}/history?limit=2000`).then(r => r.json()),
    ]);
    const samples = hist.samples || [];
    if (fmt === 'json') {
      download(`argos-host-${safe}-{stamp}.json`, JSON.stringify({
        host: { ip, label: selectedLabel || null },
        exported_at: new Date().toISOString(),
        up: sv.up ?? null,
        services: sv.services || [],
        samples,
      }, null, 2), 'application/json');
    } else {
      // CSV: serie temporal de sondeos (los datos que ha generado el host).
      const rows = [['timestamp_iso', 'timestamp_unix', 'up', 'rtt_ms']];
      samples.forEach(s => rows.push([
        new Date(s.ts * 1000).toISOString(), s.ts, s.up ? 1 : 0,
        s.rtt_ms == null ? '' : s.rtt_ms,
      ]));
      const csv = rows.map(r => r.map(csvCell).join(',')).join('\r\n');
      download(`argos-host-${safe}-{stamp}.csv`, csv, 'text/csv');
    }
    dmsg(`${fmt.toUpperCase()} exportado ✓ (${samples.length} muestras)`);
  } catch { dmsg(`error exportando ${fmt.toUpperCase()}`); }
}

function drawLatency(samples) {
  chartEl.innerHTML = '';
  const W = chartEl.clientWidth || 600, H = 150, PAD = { l: 34, r: 10, t: 10, b: 18 };
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('width', '100%'); svg.setAttribute('height', H);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
  const add = (tag, attrs, text) => {
    const el = document.createElementNS(SVG_NS, tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    if (text != null) el.textContent = text;
    svg.appendChild(el); return el;
  };
  if (!samples.length) { add('text', { x: W / 2, y: H / 2, 'text-anchor': 'middle', fill: cv('--muted', '#888'), 'font-size': 11 }, '— sin muestras aún —'); chartEl.appendChild(svg); return; }
  const rtts = samples.filter(s => s.up && s.rtt_ms != null).map(s => s.rtt_ms);
  const maxR = Math.max(10, ...rtts) * 1.2;
  const iw = W - PAD.l - PAD.r, ih = H - PAD.t - PAD.b;
  const xs = i => PAD.l + (samples.length <= 1 ? iw / 2 : (i / (samples.length - 1)) * iw);
  const ys = v => PAD.t + (1 - v / maxR) * ih;
  [0, maxR / 2, maxR].forEach(v => {
    add('line', { x1: PAD.l, x2: W - PAD.r, y1: ys(v), y2: ys(v), stroke: cv('--border', '#ccc'), opacity: 0.5 });
    add('text', { x: PAD.l - 4, y: ys(v) + 3, 'text-anchor': 'end', fill: cv('--muted', '#888'), 'font-size': 9 }, Math.round(v));
  });
  let d = '', started = false;
  samples.forEach((s, i) => { if (s.up && s.rtt_ms != null) { d += (started ? 'L' : 'M') + xs(i) + ',' + ys(s.rtt_ms); started = true; } });
  if (d) add('path', { d, fill: 'none', stroke: cv('--cyan', '#0d9488'), 'stroke-width': 1.5 });
  samples.forEach((s, i) => { if (!s.up) add('circle', { cx: xs(i), cy: H - PAD.b, r: 2.5, fill: cv('--red', '#dc2626') }); });
  add('text', { x: W - PAD.r, y: H - 4, 'text-anchor': 'end', fill: cv('--muted', '#888'), 'font-size': 9 }, 'latencia (ms) · ' + samples.length + ' muestras');
  chartEl.appendChild(svg);
}

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'hosts';
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  if (!active) { if (detailTimer) { clearInterval(detailTimer); detailTimer = null; } stopCountdown(); return; }
  showList();          // al entrar, siempre en la lista
  load();
  pollTimer = setInterval(() => { if (listPanel.hidden === false) load(); }, 10000);
});
