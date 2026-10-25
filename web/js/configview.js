// Vista "Config": estado del sistema + acciones + ajustes de la consola.
//
// Se apoya en endpoints ya existentes: /api/health, /api/ml, /api/topology,
// /api/discovery (estado) y /api/ml/retrain, /api/test-event, /api/test-flow
// (acciones). El ajuste de min_flows del Mapa se guarda en localStorage y lo
// lee mapview.js al recargar el grafo.

const statusEl = document.getElementById('config-status');
const paramsEl = document.getElementById('config-params');
const msgEl = document.getElementById('cfg-msg');
const minflowsInput = document.getElementById('cfg-minflows');

function row(k, v) {
  return `<div class="config-row"><span class="config-k">${k}</span>`
    + `<span class="config-v">${v}</span></div>`;
}
function msg(text, ok = true) {
  msgEl.textContent = text;
  msgEl.className = 'config-msg ' + (ok ? 'ok' : 'err');
}

async function loadStatus() {
  statusEl.innerHTML = 'cargando…';
  try {
    // El estado del ML (modelos heredado/local, evaluados/marcados) vive ahora
    // en Inicio; aquí dejamos solo lo técnico: servidor, topología y mapa.
    const [health, topo] = await Promise.all([
      fetch('/api/health').then(r => r.json()).catch(() => ({})),
      fetch('/api/topology').then(r => r.json()).catch(() => ({})),
    ]);
    const mf = localStorage.getItem('qs_min_flows') || '2';
    const disc = await fetch(`/api/discovery?min_flows=${encodeURIComponent(mf)}`)
      .then(r => r.json()).catch(() => ({ stats: {} }));
    const ds = disc.stats || {};
    statusEl.innerHTML =
      row('Servidor', `ARGOS NDR v${health.version || '?'} · ${health.status || '—'}`)
      + row('Topología declarada', topo.name
        ? `${topo.name} v${topo.version} · ${topo.nodes.length} nodos`
        : 'no cargada')
      + row('Descubrimiento (mapa)', `${ds.node_count || 0} nodos · ${ds.edge_count || 0} relaciones`);
  } catch (e) {
    statusEl.innerHTML = 'error cargando estado';
  }
}

function fillParams() {
  paramsEl.innerHTML =
    row('Umbral de entropía', 'H &gt; 5.0 bits')
    + row('Modelo heredado', 'RandomForest · CICIDS2017')
    + row('Modelo local', 'Isolation Forest · ventana 7 días')
    + row('Re-entrenamiento local', 'cada 6 h + al arranque')
    + row('Línea base mínima', '200 flujos')
    + row('Puertos', 'syslog 514 · NetFlow 2055');
}

document.getElementById('cfg-test-event').addEventListener('click', async () => {
  try { await fetch('/api/test-event', { method: 'POST' }); msg('evento de prueba inyectado'); }
  catch { msg('error inyectando evento', false); }
});

document.getElementById('cfg-test-flow').addEventListener('click', async () => {
  try {
    await fetch('/api/test-flow', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ anomalous: true }),
    });
    msg('flujo anómalo inyectado');
  } catch { msg('error inyectando flujo', false); }
});

document.getElementById('cfg-apply-map').addEventListener('click', () => {
  const v = Math.max(1, Math.min(100, parseInt(minflowsInput.value, 10) || 2));
  localStorage.setItem('qs_min_flows', String(v));
  minflowsInput.value = v;
  msg(`min_flows = ${v} guardado · reabre el Mapa para aplicar`);
});

document.getElementById('config-refresh').addEventListener('click', loadStatus);

// --- Tema de color ---
const THEMES = ['light', 'dark', 'ocean', 'nebula'];
const themeSel = document.getElementById('cfg-theme');

function applyTheme(theme) {
  theme = THEMES.includes(theme) ? theme : 'light';
  // 'light' es el :root por defecto → sin atributo. Los demás van en data-theme.
  if (theme === 'light') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
  try { localStorage.setItem('argos_theme', theme); } catch { /* ignore */ }
  // Avisa a las vistas que dibujan en canvas/SVG (mapa, gráfica) para re-pintar.
  document.dispatchEvent(new CustomEvent('argos:themechange', { detail: { theme } }));
}

if (themeSel) {
  themeSel.addEventListener('change', () => applyTheme(themeSel.value));
}

// --- Sensor pasivo: elegir interfaz y arrancar/parar desde la UI ---
const ifaceSel = document.getElementById('cfg-iface');
const sensorStateEl = document.getElementById('cfg-sensor-state');
const sensorMsgEl = document.getElementById('cfg-sensor-msg');

function sMsg(t, ok = true) { sensorMsgEl.textContent = t; sensorMsgEl.className = 'config-msg ' + (ok ? 'ok' : 'err'); }

async function loadInterfaces() {
  try {
    const r = await fetch('/api/interfaces').then(r => r.json());
    const ifs = (r.interfaces || []).filter(i => i.name);
    ifaceSel.innerHTML = '<option value="">(por defecto / automática)</option>'
      + ifs.map(i => {
        const ip = (i.ips && i.ips[0]) ? ` — ${i.ips[0]}` : '';
        return `<option value="${i.name.replace(/"/g, '&quot;')}">${i.name}${ip}</option>`;
      }).join('');
  } catch { ifaceSel.innerHTML = '<option>error listando</option>'; }
}

async function loadSensor() {
  try {
    const s = await fetch('/api/sensor').then(r => r.json());
    const priv = s.privileged ? '<b class="ok">● admin/root</b>' : '<b class="err">○ sin privilegios (no podrá capturar)</b>';
    const paq = (s.stats && s.stats.packets != null) ? ` · ${s.stats.packets} paq` : '';
    sensorStateEl.innerHTML =
      row('Sensor', s.running ? `<b class="ok">● activo</b> (${s.iface || 'default'})${paq}` : '○ detenido')
      + row('Privilegios', priv);
    if (s.iface) ifaceSel.value = s.iface;
  } catch { sensorStateEl.innerHTML = row('Sensor', 'error'); }
}

document.getElementById('cfg-sensor-start').addEventListener('click', async () => {
  sMsg('iniciando el sensor…');
  try {
    const r = await fetch('/api/sensor/start', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iface: ifaceSel.value || null }),
    }).then(r => r.json());
    if (r.running) sMsg(`sensor capturando en ${r.iface || 'default'}`);
    else sMsg(r.error || 'no se pudo iniciar', false);
    loadSensor();
  } catch { sMsg('error al iniciar', false); }
});

document.getElementById('cfg-sensor-stop').addEventListener('click', async () => {
  try { await fetch('/api/sensor/stop', { method: 'POST' }); sMsg('sensor detenido'); loadSensor(); }
  catch { sMsg('error al detener', false); }
});

// --- Exportar datos a JSON ---
function downloadJSON(name, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  a.href = url; a.download = `argos-${name}-${stamp}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const EXPORTS = {
  inventario: () => fetch('/api/discovery?min_flows=1').then(r => r.json()),
  flujos: () => fetch('/api/flows?limit=2000').then(r => r.json()),
  anomalias: () => fetch('/api/history?limit=2000&anomaly_only=true').then(r => r.json()),
  mapa: () => fetch('/api/discovery').then(r => r.json()),
};

document.querySelector('[data-export="todo"]').closest('.config-inline')
  .addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-export]');
    if (!btn) return;
    const kind = btn.dataset.export;
    const em = document.getElementById('cfg-export-msg');
    em.textContent = `exportando ${kind}…`; em.className = 'config-msg ok';
    try {
      if (kind === 'todo') {
        const [inv, flows, anom] = await Promise.all([
          EXPORTS.inventario(), EXPORTS.flujos(), EXPORTS.anomalias()]);
        downloadJSON('export-completo', {
          exported_at: new Date().toISOString(),
          inventario: inv, flujos: flows, anomalias: anom,
        });
      } else {
        downloadJSON(kind, await EXPORTS[kind]());
      }
      em.textContent = `${kind} exportado ✓`;
    } catch { em.textContent = `error exportando ${kind}`; em.className = 'config-msg err'; }
  });

document.addEventListener('viewchange', (e) => {
  if (e.detail.id !== 'config') return;
  minflowsInput.value = localStorage.getItem('qs_min_flows') || '2';
  if (themeSel) themeSel.value = localStorage.getItem('argos_theme') || 'light';
  fillParams();
  loadStatus();
  loadInterfaces();
  loadSensor();
});
