// Vista "SOAR": respuesta automática. Muestra el modo de operación
// (Manual / Automático), el estado del motor de bloqueo y la lista de IPs
// bloqueadas, y permite bloquear/desbloquear una IP a mano.
//
// * Manual  → las amenazas se detectan y se muestran, pero el operador decide
//             qué IP bloquear (botón «Bloquear»).
// * Auto    → un hit de honeypot o un flood/DoS dispara el bloqueo por sí solo,
//             respetando la lista blanca (gateway, IP propia, DNS…).
//
// El backend expone: GET /api/soar, POST /api/soar/mode, GET /api/soar/blocked,
// POST /api/block, POST /api/unblock.

const statusEl = document.getElementById('soar-status');
const stateEl = document.getElementById('soar-state');
const hintEl = document.getElementById('soar-mode-hint');
const msgEl = document.getElementById('soar-msg');
const btnManual = document.getElementById('soar-mode-manual');
const btnAuto = document.getElementById('soar-mode-auto');
const ipInput = document.getElementById('soar-ip');
const blockBtn = document.getElementById('soar-block');
const blockedBody = document.getElementById('soar-blocked-body');
const blockedEmpty = document.getElementById('soar-blocked-empty');

let active = false;

const HINTS = {
  manual: '<b>Manual:</b> las amenazas se detectan y se muestran, pero tú decides qué IP bloquear.',
  auto: '<b>Automático:</b> un hit de honeypot o un flood/DoS bloquea la IP por sí solo (respeta la lista blanca).',
};

function esc(s) { return String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function row(k, v) {
  return `<div class="config-row"><span class="config-k">${k}</span>`
    + `<span class="config-v">${v}</span></div>`;
}
function msg(text, ok = true) {
  msgEl.textContent = text;
  msgEl.className = 'config-msg ' + (ok ? 'ok' : 'err');
}
function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString('es', { hour12: false });
}

function setModeUI(mode) {
  const auto = mode === 'auto';
  // Reutilizamos los estilos ya definidos: cian (seguro) para manual, rojo
  // (armado) para automático. El botón activo pierde el look "muted".
  btnManual.className = 'btn-action soar-mode-btn' + (auto ? '' : ' btn-reactivate active');
  btnAuto.className = 'btn-action soar-mode-btn' + (auto ? ' btn-isolate active' : '');
  hintEl.innerHTML = HINTS[mode] || '';
}

function renderState(s) {
  const priv = s.privileged
    ? '<b class="hp-on">● admin/root</b>'
    : '<b class="hp-off">○ sin privilegios — los bloqueos fallarán</b>';
  stateEl.innerHTML =
      row('Modo activo', s.mode === 'auto'
        ? '<b class="soar-armed">● AUTOMÁTICO</b>' : '<b class="hp-on">● MANUAL</b>')
    + row('Privilegios', priv)
    + row('Plataforma', esc(s.platform || '—'))
    + row('Cooldown', `${s.cooldown_s ?? '—'} s`)
    + row('Bloqueos activos', s.active_count || 0)
    + row('Auto / Manual', `${s.auto_blocks || 0} / ${s.manual_blocks || 0}`)
    + row('En lista blanca', (s.allowlist || []).length + ' entradas');
  setModeUI(s.mode);
  statusEl.textContent = `modo ${s.mode} · ${s.active_count || 0} bloqueada(s)`;
}

function renderBlocked(list) {
  const rows = (list || []).map(b => {
    const estado = b.active
      ? '<span class="badge-anom">● activo</span>'
      : '<span class="badge-ok">retirado</span>';
    const acc = b.active
      ? `<button class="btn-action btn-reactivate soar-unblock" data-ip="${esc(b.ip)}">Desbloquear</button>`
      : '';
    return `<tr>`
      + `<td class="mono muted">${fmtTime((b.ts || 0) * 1000)}</td>`
      + `<td class="mono">${esc(b.ip)}</td>`
      + `<td class="muted">${esc(b.reason || '—')}</td>`
      + `<td class="muted">${esc(b.actor || '—')}</td>`
      + `<td>${estado}</td><td>${acc}</td></tr>`;
  }).join('');
  blockedBody.innerHTML = rows;
  blockedEmpty.style.display = rows ? 'none' : '';
}

async function load() {
  try {
    const [s, b] = await Promise.all([
      fetch('/api/soar').then(r => r.json()),
      fetch('/api/soar/blocked').then(r => r.json()),
    ]);
    renderState(s);
    renderBlocked(b.blocked);
  } catch {
    statusEl.textContent = 'error consultando el SOAR';
  }
}

async function setMode(mode) {
  msg('cambiando modo…');
  try {
    const r = await fetch('/api/soar/mode', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode }),
    }).then(r => r.json());
    if (r.error) { msg(r.error, false); return; }
    msg(r.mode === 'auto'
      ? 'modo AUTOMÁTICO — ARGOS bloqueará las amenazas por sí solo'
      : 'modo MANUAL — tú decides qué bloquear');
    renderState(r);
  } catch { msg('no se pudo cambiar el modo', false); }
}

btnManual.addEventListener('click', () => setMode('manual'));
btnAuto.addEventListener('click', () => setMode('auto'));

blockBtn.addEventListener('click', async () => {
  const ip = (ipInput.value || '').trim();
  if (!ip) { msg('escribe una IP', false); return; }
  msg('bloqueando…');
  try {
    const r = await fetch('/api/block', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason: 'bloqueo manual' }),
    }).then(r => r.json());
    if (r.ok) { msg(`IP ${ip} bloqueada en el firewall`); ipInput.value = ''; }
    else if (r.skipped) msg(`no se bloquea: ${r.reason}`, false);
    else msg(`no se pudo bloquear (${r.output || 'error'})`, false);
    load();
  } catch { msg('error al bloquear', false); }
});

// Desbloqueo — delegado en el tbody.
blockedBody.addEventListener('click', async (e) => {
  const btn = e.target.closest('.soar-unblock');
  if (!btn) return;
  const ip = btn.dataset.ip;
  btn.disabled = true;
  msg(`desbloqueando ${ip}…`);
  try {
    const r = await fetch('/api/unblock', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    }).then(r => r.json());
    msg(r.ok ? `IP ${ip} desbloqueada` : `no se pudo desbloquear (${r.output || 'error'})`, !!r.ok);
    load();
  } catch { msg('error al desbloquear', false); }
});

// Un bloqueo automático llega como evento por el WS: refrescamos si la vista
// está abierta para que la lista y los contadores no queden viejos.
document.addEventListener('qs:event', (e) => {
  const ev = e.detail;
  if (active && ev && ev.blocked) load();
});

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'soar';
  if (active) load();
});
