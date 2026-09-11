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
    const [health, ml, topo] = await Promise.all([
      fetch('/api/health').then(r => r.json()).catch(() => ({})),
      fetch('/api/ml').then(r => r.json()).catch(() => ({})),
      fetch('/api/topology').then(r => r.json()).catch(() => ({})),
    ]);
    const mf = localStorage.getItem('qs_min_flows') || '2';
    const disc = await fetch(`/api/discovery?min_flows=${encodeURIComponent(mf)}`)
      .then(r => r.json()).catch(() => ({ stats: {} }));
    const loc = ml.local || {};
    const ds = disc.stats || {};
    statusEl.innerHTML =
      row('Servidor', `ARGOS NDR v${health.version || '?'} · ${health.status || '—'}`)
      + row('Detector heredado', ml.inherited_loaded ? 'activo' : 'no cargado')
      + row('Modelo local', loc.ready
        ? `listo (${loc.train_size} flujos)`
        : `entrenando ${loc.train_size || 0}/${loc.min_flows || 200}`)
      + row('Flujos evaluados / marcados', `${ml.evaluated || 0} / ${ml.flagged || 0}`)
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

document.getElementById('cfg-retrain').addEventListener('click', async () => {
  msg('re-entrenando…');
  try {
    const r = await fetch('/api/ml/retrain', { method: 'POST' }).then(r => r.json());
    const loc = r.local || {};
    msg(r.ready
      ? `modelo local re-entrenado (${loc.train_size} flujos)`
      : `sin datos suficientes (${loc.train_size || 0}/${loc.min_flows || 200})`, !!r.ready);
    loadStatus();
  } catch { msg('error al re-entrenar', false); }
});

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

document.addEventListener('viewchange', (e) => {
  if (e.detail.id !== 'config') return;
  minflowsInput.value = localStorage.getItem('qs_min_flows') || '2';
  fillParams();
  loadStatus();
});
