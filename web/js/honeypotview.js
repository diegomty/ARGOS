// Vista "Honeypot": estado de los señuelos + control (activar/desactivar) y
// una prueba en vivo. Cada conexión a un puerto trampa es una amenaza real de
// alta confianza; aquí se ven los "hits" a medida que ocurren.
//
// Los hits llegan como eventos anómalos por el WebSocket (qs:event, reemitido
// por main.js); los reconocemos porque su raw_message empieza con "HONEYPOT".

const statusEl = document.getElementById('hp-status');
const stateEl = document.getElementById('hp-state');
const portsEl = document.getElementById('hp-ports');
const hitsEl = document.getElementById('hp-hits');
const emptyEl = document.getElementById('hp-empty');
const msgEl = document.getElementById('hp-msg');
const toggleBtn = document.getElementById('hp-toggle');
const testBtn = document.getElementById('hp-test');

const MAX = 200;
let loaded = false, active = false;

function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString('es', { hour12: false })
    + '.' + String(d.getMilliseconds()).padStart(3, '0');
}
function esc(s) { return String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }

function renderState(s) {
  const on = s.running;
  stateEl.innerHTML =
      `<div class="config-row"><span>Honeypot</span>`
    +   `<b class="${on ? 'hp-on' : 'hp-off'}">${on ? '● ACTIVO' : '○ apagado'}</b></div>`
    + `<div class="config-row"><span>Hits totales</span><b>${s.hits || 0}</b></div>`
    + `<div class="config-row"><span>Errores</span><b>${s.errors || 0}</b></div>`;
  toggleBtn.textContent = on ? 'Desactivar honeypot' : 'Activar honeypot';
  testBtn.disabled = !on;
  statusEl.textContent = on
    ? `activo · ${(s.puertos || []).length} señuelos · ${s.hits || 0} hits`
    : 'apagado';

  const serv = s.servicios || {};
  portsEl.innerHTML = (s.puertos || []).map(p =>
    `<div class="config-row"><span>puerto ${p}</span>`
    + `<b class="mono">${esc(serv[p] || '—')}</b></div>`).join('');
}

async function load() {
  try {
    const s = await fetch('/api/honeypot').then(r => r.json());
    renderState(s);
    loaded = true;
  } catch {
    statusEl.textContent = 'error consultando el honeypot';
  }
}

// Un hit = un evento anómalo cuyo mensaje empieza con "HONEYPOT".
function addHit(ev) {
  const msg = ev.raw_message || '';
  // "HONEYPOT ssh:2222 <- 10.0.0.2:51344 data=..."
  const señuelo = (msg.match(/HONEYPOT (\S+)/) || [])[1] || '—';
  const datos = (msg.match(/data=(.*)$/) || [])[1] || '';
  const row =
      `<tr>`
    + `<td class="mono muted">${fmtTime(ev.received_at ? ev.received_at * 1000 : Date.now())}</td>`
    + `<td class="mono">${esc(ev.attacker_ip || ev.source_ip || '—')}</td>`
    + `<td><span class="badge-anom">${esc(señuelo)}</span></td>`
    + `<td class="mono muted">${esc(datos.slice(0, 80)) || '(sin datos)'}</td></tr>`;
  emptyEl.style.display = 'none';
  hitsEl.insertAdjacentHTML('afterbegin', row);
  while (hitsEl.children.length > MAX) hitsEl.removeChild(hitsEl.lastChild);
}

toggleBtn.addEventListener('click', async () => {
  toggleBtn.disabled = true;
  msgEl.textContent = 'aplicando…';
  try {
    const r = await fetch('/api/honeypot/toggle', { method: 'POST' }).then(r => r.json());
    msgEl.textContent = r.running ? 'honeypot activado' : 'honeypot desactivado';
    await load();
  } catch {
    msgEl.textContent = 'no se pudo cambiar el estado';
  } finally {
    toggleBtn.disabled = false;
  }
});

testBtn.addEventListener('click', async () => {
  msgEl.textContent = 'lanzando conexión de prueba a un señuelo…';
  try {
    const r = await fetch('/api/honeypot/test', { method: 'POST' }).then(r => r.json());
    msgEl.textContent = r.ok
      ? `hit generado en el señuelo ${r.service}:${r.port} → míralo abajo y en Anomalías`
      : (r.error || 'no se pudo probar');
    load();
  } catch {
    msgEl.textContent = 'error al probar el señuelo';
  }
});

// Hits en vivo desde el WebSocket.
document.addEventListener('qs:event', (e) => {
  const ev = e.detail;
  if (ev && (ev.raw_message || '').startsWith('HONEYPOT')) addHit(ev);
});

document.addEventListener('viewchange', (e) => {
  active = e.detail.id === 'honeypot';
  if (active) load();
});
