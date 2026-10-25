// Vista "Inicio" — Centro de operaciones (landing).
//
// Reúne la historia del producto en una pantalla: el estado del "sistema
// inmune" (los 2 modelos de ML), KPIs en vivo y un feed de amenazas.
// Fuentes: /api/ml (detector), /api/health, /api/hosts, /api/discovery, y los
// eventos en vivo qs:flow / qs:event que main.js reemite desde el WebSocket.

const statusEl = document.getElementById('home-status');
const miDot = document.getElementById('mi-dot');
const miState = document.getElementById('mi-state');
const mlDot = document.getElementById('ml-dot');
const mlState = document.getElementById('ml-state');
const mlBar = document.getElementById('ml-bar');
const mlProgLbl = document.getElementById('ml-prog-lbl');
const retrainBtn = document.getElementById('home-retrain');
const retrainMsg = document.getElementById('home-retrain-msg');

const kEval = document.getElementById('kpi-eval');
const kFlagged = document.getElementById('kpi-flagged');
const kHosts = document.getElementById('kpi-hosts');
const kNet = document.getElementById('kpi-net');

const feedEl = document.getElementById('home-feed');
const feedEmpty = document.getElementById('home-feed-empty');
const feedHint = document.getElementById('home-feed-hint');

const FEED_MAX = 15;
let active = false, pollTimer = null, feedCount = 0;

function esc(s) { return String(s == null ? '' : s).replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function pill(cls, text) { return `<span class="det ${cls}">${esc(text)}</span>`; }
function fmtTime(t) {
  const d = new Date(t);
  return d.toLocaleTimeString('es', { hour12: false });
}
function fmtBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return (b || 0) + ' B';
}

// ---------- Modelos (sistema inmune) ----------
function renderModels(ml) {
  // Heredado (RandomForest / CICIDS)
  if (ml.inherited_loaded) {
    miDot.className = 'model-dot on';
    miState.innerHTML = '<b class="ok">● activo</b> — modelo cargado y evaluando';
  } else {
    miDot.className = 'model-dot off';
    miState.innerHTML = '○ no entrenado — corre <code>python -m ml.train</code>';
  }
  // Local (Isolation Forest)
  const loc = ml.local || {};
  const size = loc.train_size || 0, min = loc.min_flows || 200;
  if (loc.ready) {
    mlDot.className = 'model-dot on';
    mlState.innerHTML = `<b class="ok">● listo</b> — línea base de ${size} flujos`;
    mlBar.style.width = '100%';
    mlProgLbl.textContent = 'aprendiendo continuamente de tu red';
  } else {
    mlDot.className = 'model-dot warn';
    mlState.innerHTML = 'aprendiendo la línea base…';
    mlBar.style.width = Math.min(100, (size / min) * 100).toFixed(0) + '%';
    mlProgLbl.textContent = `${size} / ${min} flujos para empezar a opinar`;
  }
}

function renderKpis(ml, hosts, disc) {
  kEval.textContent = (ml.evaluated || 0).toLocaleString('es');
  kFlagged.textContent = (ml.flagged || 0).toLocaleString('es');
  if (hosts) {
    const list = hosts.hosts || [];
    const up = list.filter(h => h.up === true).length;
    kHosts.textContent = `${up} / ${list.length}`;
  }
  if (disc && disc.stats) kNet.textContent = `${disc.stats.node_count || 0} · ${disc.stats.edge_count || 0}`;
}

async function loadAll() {
  try {
    const [ml, health, hosts, disc] = await Promise.all([
      fetch('/api/ml').then(r => r.json()).catch(() => ({})),
      fetch('/api/health').then(r => r.json()).catch(() => ({})),
      fetch('/api/hosts').then(r => r.json()).catch(() => ({})),
      fetch('/api/discovery').then(r => r.json()).catch(() => ({})),
    ]);
    statusEl.textContent = `ARGOS NDR v${health.version || '?'} · ${health.status || '—'}`;
    renderModels(ml);
    renderKpis(ml, hosts, disc);
  } catch { statusEl.textContent = 'error cargando estado'; }
}

retrainBtn.addEventListener('click', async () => {
  retrainMsg.textContent = 're-entrenando el modelo local…';
  retrainBtn.disabled = true;
  try {
    const r = await fetch('/api/ml/retrain', { method: 'POST' }).then(r => r.json());
    const loc = r.local || {};
    retrainMsg.textContent = r.ready
      ? `modelo local listo (${loc.train_size} flujos) ✓`
      : `sin datos suficientes (${loc.train_size || 0}/${loc.min_flows || 200})`;
    loadAll();
  } catch { retrainMsg.textContent = 'error al re-entrenar'; }
  finally { retrainBtn.disabled = false; }
});

// ---------- Feed de amenazas en vivo ----------
function addFeed(time, src, detail, badges) {
  feedEmpty.style.display = 'none';
  const row = document.createElement('div');
  row.className = 'feed-row';
  row.innerHTML = `<span class="feed-time">${fmtTime(time)}</span>`
    + `<span class="feed-src">${esc(src)}</span>`
    + `<span class="feed-det">${detail}</span>${badges}`;
  feedEl.insertBefore(row, feedEl.firstChild);   // más reciente arriba
  feedCount++;
  while (feedEl.querySelectorAll('.feed-row').length > FEED_MAX) {
    feedEl.removeChild(feedEl.querySelector('.feed-row:last-child'));
  }
  feedHint.textContent = `${feedCount} en esta sesión`;
}

document.addEventListener('qs:flow', (e) => {
  const f = e.detail;
  if (!f || !f.ml || !f.ml.is_anomaly) return;
  const inh = f.ml.inherited, loc = f.ml.local;
  let badges = '';
  if (inh && inh.is_attack) badges += pill('det-inherited', `RF ${Math.round((inh.confidence || 0) * 100)}%`);
  if (loc && loc.is_anomaly) badges += pill('det-local', 'IsoForest');
  if (!badges) badges = pill('det-rule', 'anómalo');
  addFeed(Date.now(), f.src_ip || '—', `→ ${esc(f.dst_ip)}:${f.dst_port} · ${fmtBytes(f.bytes)}`, badges);
  // refleja el conteo al instante sin esperar al poll (el poll lo corrige luego)
  const cur = parseInt(kFlagged.textContent.replace(/\D/g, ''), 10) || 0;
  kFlagged.textContent = (cur + 1).toLocaleString('es');
});

document.addEventListener('qs:event', (e) => {
  const ev = e.detail;
  if (!ev || !ev.is_anomaly) return;
  const H = Number(ev.entropy);
  const badges = pill('det-rule', `H=${isFinite(H) ? H.toFixed(2) : '?'}`);
  addFeed(ev.received_at ? ev.received_at * 1000 : Date.now(),
    ev.attacker_ip || ev.source_ip || '—',
    esc((ev.raw_message || '').slice(0, 60)), badges);
});

// ---------- Ciclo de vida ----------
function enter() {
  active = true;
  loadAll();
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => { if (active) loadAll(); }, 7000);
}
function leave() {
  active = false;
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

document.addEventListener('viewchange', (e) => {
  if (e.detail.id === 'inicio') enter(); else leave();
});

// console.js no dispara viewchange en la carga inicial: si Inicio es la vista
// activa de arranque, la inicializamos aquí.
if (document.querySelector('.view-inicio.active')) enter();
