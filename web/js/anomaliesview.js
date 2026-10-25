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

function pill(cls, text) { return `<span class="det ${cls}">${esc(text)}</span>`; }

function eventItem(ev) {
  const H = Number(ev.entropy);
  let badges = pill('det-rule', `Entropía · H=${isFinite(H) ? H.toFixed(2) : '?'}`);
  if (ev.plan && ev.plan !== 'NONE') badges += pill('det-plan', `Plan ${ev.plan}`);
  return {
    type: 'evento',
    t: ev.received_at ? ev.received_at * 1000 : Date.now(),
    src: ev.attacker_ip || ev.source_ip || '—',
    ip: ev.attacker_ip || ev.source_ip || null,
    detail: esc((ev.raw_message || '').slice(0, 72)) || '—',
    badges,
    reason: 'Entropía alta en el contenido — regla, no ML',
    blocked: !!ev.blocked,
  };
}

function flowItem(f) {
  const ml = f.ml || {};
  const inh = ml.inherited, loc = ml.local;
  let badges = '';
  if (inh && inh.is_attack)
    badges += pill('det-inherited', `RandomForest · ${Math.round((inh.confidence || 0) * 100)}% ataque`);
  if (loc && loc.is_anomaly) {
    const s = Number(loc.score);
    badges += pill('det-local', `IsolationForest · score ${isFinite(s) ? (s >= 0 ? '+' : '') + s.toFixed(2) : '?'}`);
  }
  if (!badges) badges = pill('det-rule', 'anómalo');
  let reason;
  if (inh && inh.is_attack && loc && loc.is_anomaly)
    reason = 'Patrón de ataque conocido + se desvía de tu línea base';
  else if (inh && inh.is_attack)
    reason = 'Coincide con un patrón de ataque conocido (modelo heredado)';
  else if (loc && loc.is_anomaly)
    reason = 'Se desvía de la línea base normal de tu red (modelo local)';
  else
    reason = 'Marcado por el detector';
  return {
    type: 'flujo',
    t: Date.now(),
    src: `${f.src_ip}:${f.src_port}`,
    ip: f.src_ip || null,
    detail: `→ ${esc(f.dst_ip)} :${f.dst_port} · ${fmtBytes(f.bytes)}`,
    badges,
    reason,
    blocked: false,
  };
}

function actionCell(it) {
  if (it.blocked) return '<span class="badge-anom">bloqueado ✓</span>';
  if (!it.ip) return '<span class="muted">—</span>';
  return `<button class="btn-action tbl-act anom-block" data-ip="${esc(it.ip)}">Bloquear</button>`;
}

function rowHtml(it) {
  return `<tr>`
    + `<td class="mono muted">${fmtTime(it.t)}</td>`
    + `<td><span class="badge-tipo ${it.type}">${it.type}</span></td>`
    + `<td class="mono">${esc(it.src)}</td>`
    + `<td>${it.detail}</td>`
    + `<td>${it.badges}<div class="anom-reason">${esc(it.reason)}</div></td>`
    + `<td>${actionCell(it)}</td></tr>`;
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

// Acción Bloquear directa desde la fila (cierra el ciclo detección → respuesta).
tbody.addEventListener('click', async (e) => {
  const btn = e.target.closest('.anom-block');
  if (!btn) return;
  const ip = btn.dataset.ip;
  btn.disabled = true; btn.textContent = 'bloqueando…';
  try {
    const r = await fetch('/api/block', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason: 'bloqueo manual (Anomalías)' }),
    }).then(r => r.json());
    if (r.ok) {
      btn.outerHTML = '<span class="badge-anom">bloqueado ✓</span>';
    } else {
      btn.disabled = false;
      btn.textContent = 'Bloquear';
      btn.title = r.skipped ? 'no se bloquea: ' + r.reason : 'no se pudo bloquear';
    }
  } catch {
    btn.disabled = false; btn.textContent = 'Bloquear'; btn.title = 'error al bloquear';
  }
});

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'anomalias';
  if (!active) return;
  if (!loaded || Date.now() - lastFetch > 8000) load();
  else { render(); loadStatus(); }
});
