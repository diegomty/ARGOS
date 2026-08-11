// Vista "Mapa de Red": grafo force-directed de la topología autodescubierta.
//
// Consume /api/discovery y dibuja el grafo con una simulación de fuerzas
// propia (repulsión entre nodos + resortes en las aristas + gravedad al
// centro) sobre un canvas 2D — sin librerías externas. El layout emerge
// solo, igual que en la imagen de referencia: nadie fija posiciones.
//
// Solo simula/renderiza mientras la vista "map" está activa (lo indica el
// evento `viewchange` que emite console.js), para no gastar CPU oculto.

const canvas = document.getElementById('map-canvas');
const ctx = canvas.getContext('2d');
const statusEl = document.getElementById('map-status');
const emptyEl = document.getElementById('map-empty');

// Tooltip HTML (se crea al vuelo dentro del contenedor del canvas).
const tip = document.createElement('div');
tip.className = 'map-tip';
tip.style.display = 'none';
canvas.parentElement.appendChild(tip);

// --- Paleta por rol (respaldo cuando el nodo no trae color_hint) ---
const ROLE_COLOR = {
  database: '#f5c14b', dns: '#a78bfa', 'windows-server': '#5ee0d6',
  'mail-server': '#60a5fa', 'web-server': '#7cf09a', 'file-server': '#f59e0b',
  'ssh-host': '#94a3b8', scanner: '#ff4d6d', workstation: '#b8c4d6',
  host: '#6c7a99',
};
const CRIT_COLOR = { critical: '#ff4d6d', high: '#f5c14b', medium: '#60a5fa' };

// --- Parámetros de la simulación (afinados para decenas de nodos) ---
const REPULSION = 7000;
const SPRING = 0.03;
const REST_LEN = 115;
const GRAVITY = 0.03;
const FRICTION = 0.6;       // fricción fuerte: retiene 60% de la velocidad
const MAX_SPEED = 28;       // límite anti-explosión por paso
const ALPHA_DECAY = 0.98;   // enfriamiento: las fuerzas menguan hasta asentar
const ALPHA_MIN = 0.02;     // por debajo, el grafo se considera quieto
const CLUSTER_STRENGTH = 0.08;  // atracción de cada nodo hacia el ancla de su grupo
let alpha = 1;              // "temperatura" de la simulación (decae a 0)
let clustered = false;      // layout por clústeres (agrupado por zona) activo

let nodes = [];
let edges = [];
let byId = new Map();
let W = 0, H = 0, dpr = 1;
let running = false, loaded = false, lastFetch = 0, raf = null;
let hoverNode = null, dragNode = null;

// Cámara: desplazamiento (pan) + escala (zoom). El mundo del grafo se dibuja
// bajo esta transformación, de modo que mover/acercar es independiente del
// layout: las posiciones de los nodos no cambian al manipular la vista.
const cam = { x: 0, y: 0, scale: 1 };
let userInteracted = false, fitted = false;

// Enfoque: al hacer clic en un nodo se resaltan él y sus vecinos, y el resto
// se atenúa. `press` distingue un clic (enfocar) de un arrastre (mover/pan).
let focusNode = null, focusSet = new Set();
let press = null;
const CLICK_MOVE = 4;   // px de tolerancia para considerar que fue un clic

function resize() {
  const wrap = canvas.parentElement;
  const w = wrap.clientWidth, h = wrap.clientHeight;
  if (!w || !h) return;
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = w * dpr; canvas.height = h * dpr;
  canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  W = w; H = h;
}

async function load() {
  try {
    // min_flows configurable desde el módulo Config (persistido en localStorage).
    const mf = localStorage.getItem('qs_min_flows') || '2';
    const g = await fetch(`/api/discovery?min_flows=${encodeURIComponent(mf)}`).then(r => r.json());
    const cx = W / 2, cy = H / 2;
    nodes = g.nodes.map((n, i) => {
      const a = (i / g.nodes.length) * Math.PI * 2;
      return {
        ...n,
        x: cx + Math.cos(a) * 140 + (Math.random() - 0.5) * 20,
        y: cy + Math.sin(a) * 140 + (Math.random() - 0.5) * 20,
        vx: 0, vy: 0,
        r: 6 + Math.min(16, Math.log2((n.flows || 1) + 1) * 2.1),
      };
    });
    byId = new Map(nodes.map(n => [n.id, n]));
    edges = g.edges.filter(e => byId.has(e.source) && byId.has(e.target));
    loaded = true; lastFetch = Date.now();
    organize();  // layout agrupado por zona desde el inicio (ordenado)
    emptyEl.style.display = 'none';
    const s = g.stats || {};
    statusEl.textContent =
      `${s.node_count || nodes.length} nodos · ${s.edge_count || edges.length} relaciones · `
      + `${s.scanners || 0} scanner(s)   ·   arrastra: mover · rueda: zoom · `
      + `arrastra nodo: fijar · doble clic: reorganizar`;
  } catch (err) {
    statusEl.textContent = 'no se pudo cargar /api/discovery';
    emptyEl.textContent = 'Error cargando el mapa: ' + err;
  }
}

function step() {
  const cx = W / 2, cy = H / 2;
  // Acumuladores de fuerza frescos cada paso (no se mezclan con la velocidad).
  for (const n of nodes) { n.fx = 0; n.fy = 0; }
  // Repulsión O(n^2) — trivial para decenas de nodos.
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 0.01;
      const d = Math.sqrt(d2);
      const f = REPULSION / d2;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      a.fx += fx; a.fy += fy; b.fx -= fx; b.fy -= fy;
    }
  }
  // Resortes en las aristas.
  for (const e of edges) {
    const a = byId.get(e.source), b = byId.get(e.target);
    let dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const f = (d - REST_LEN) * SPRING;
    const fx = (dx / d) * f, fy = (dy / d) * f;
    a.fx += fx; a.fy += fy; b.fx -= fx; b.fy -= fy;
  }
  // Cohesión: cada nodo se atrae hacia el ancla de su grupo (clústeres por
  // zona) o, si no hay layout agrupado, hacia el centro (gravedad simple).
  for (const n of nodes) {
    if (clustered && n.gx != null) {
      n.fx += (n.gx - n.x) * CLUSTER_STRENGTH;
      n.fy += (n.gy - n.y) * CLUSTER_STRENGTH;
    } else {
      n.fx += (cx - n.x) * GRAVITY;
      n.fy += (cy - n.y) * GRAVITY;
    }
  }
  // Integración: la fuerza (escalada por alpha) alimenta la velocidad, que se
  // frena con fricción y se limita. Al decaer alpha, el sistema se detiene.
  for (const n of nodes) {
    if (n === dragNode || n.fixed) { n.vx = 0; n.vy = 0; continue; }
    n.vx = (n.vx + n.fx * alpha) * FRICTION;
    n.vy = (n.vy + n.fy * alpha) * FRICTION;
    const sp = Math.hypot(n.vx, n.vy);
    if (sp > MAX_SPEED) { n.vx *= MAX_SPEED / sp; n.vy *= MAX_SPEED / sp; }
    n.x += n.vx; n.y += n.vy;
  }
  alpha *= ALPHA_DECAY;
}

function nodeColor(n) {
  return n.color_hint || ROLE_COLOR[n.role] || '#6c7a99';
}

function draw() {
  // Limpia en espacio de pantalla, luego aplica la cámara (pan + zoom) para
  // dibujar el grafo en coordenadas de mundo.
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, W, H);
  ctx.translate(cam.x, cam.y);
  ctx.scale(cam.scale, cam.scale);

  // Aristas primero (más gruesas = más volumen; rojas si tocan escaneo).
  for (const e of edges) {
    const a = byId.get(e.source), b = byId.get(e.target);
    // Con un nodo enfocado, solo sus aristas se ven; el resto se atenúa.
    const shown = !focusNode || e.source === focusNode.id || e.target === focusNode.id;
    ctx.globalAlpha = shown ? 1 : 0.05;
    const threat = b.is_scan_target || a.is_scanner;
    ctx.strokeStyle = threat ? 'rgba(255,77,109,0.5)' : 'rgba(94,224,214,0.13)';
    ctx.lineWidth = 0.5 + Math.min(5, Math.log2((e.flows || 1) + 1));
    ctx.beginPath();
    ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    // Punta de flecha (dirección origen -> destino) al 72% del trayecto.
    const ang = Math.atan2(b.y - a.y, b.x - a.x);
    const hx = a.x + (b.x - a.x) * 0.72, hy = a.y + (b.y - a.y) * 0.72;
    ctx.fillStyle = threat ? 'rgba(255,77,109,0.6)' : 'rgba(94,224,214,0.28)';
    ctx.beginPath();
    ctx.moveTo(hx, hy);
    ctx.lineTo(hx - 6 * Math.cos(ang - 0.4), hy - 6 * Math.sin(ang - 0.4));
    ctx.lineTo(hx - 6 * Math.cos(ang + 0.4), hy - 6 * Math.sin(ang + 0.4));
    ctx.fill();
  }

  // Nodos.
  ctx.globalAlpha = 1;
  ctx.font = '10px ui-monospace, Consolas, monospace';
  ctx.textAlign = 'center';
  for (const n of nodes) {
    const shown = !focusNode || focusSet.has(n.id);
    ctx.globalAlpha = shown ? 1 : 0.08;
    const col = nodeColor(n);
    // Halo suave.
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
    ctx.fillStyle = col + '22'; ctx.fill();
    // Núcleo.
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = col; ctx.fill();
    // Anillo de criticidad.
    if (n.criticality && CRIT_COLOR[n.criticality]) {
      ctx.strokeStyle = CRIT_COLOR[n.criticality]; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 3, 0, Math.PI * 2); ctx.stroke();
    }
    // Marca de amenaza (escaneado o escáner): anillo rojo punteado.
    if (n.is_scan_target || n.is_scanner) {
      ctx.strokeStyle = '#ff4d6d'; ctx.lineWidth = 1.5;
      ctx.setLineDash([3, 3]);
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 7, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]);
    }
    // Resalte en hover.
    if (n === hoverNode) {
      ctx.strokeStyle = '#ffffff'; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 10, 0, Math.PI * 2); ctx.stroke();
    }
    // Etiqueta.
    ctx.fillStyle = n === hoverNode ? '#d6dee8' : 'rgba(214,222,232,0.6)';
    ctx.fillText(n.label || n.ip, n.x, n.y + n.r + 13);
  }
  ctx.globalAlpha = 1;
}

function frame() {
  if (!running) return;
  if (alpha > ALPHA_MIN) step();   // solo simula mientras no se ha asentado
  // Auto-encuadre una vez que el layout casi se asentó, si el usuario aún no
  // manipuló la vista — así el grafo aparece centrado y a escala.
  if (!userInteracted && !fitted && alpha < 0.15) { fitView(); fitted = true; }
  draw();
  raf = requestAnimationFrame(frame);
}

function fitToNodes(list, pad = 70, maxScale = 1.8) {
  list = list.filter(Boolean);
  if (!list.length) return;
  let minx = Infinity, miny = Infinity, maxx = -Infinity, maxy = -Infinity;
  for (const n of list) {
    minx = Math.min(minx, n.x - n.r); miny = Math.min(miny, n.y - n.r);
    maxx = Math.max(maxx, n.x + n.r); maxy = Math.max(maxy, n.y + n.r);
  }
  const gw = (maxx - minx) || 1, gh = (maxy - miny) || 1;
  cam.scale = Math.max(0.25, Math.min((W - pad * 2) / gw, (H - pad * 2) / gh, maxScale));
  cam.x = W / 2 - ((minx + maxx) / 2) * cam.scale;
  cam.y = H / 2 - ((miny + maxy) / 2) * cam.scale;
}
function fitView() { fitToNodes(nodes, 70, 1.8); }

// Enfoca un nodo: resalta él + sus vecinos y hace zoom para verlos.
function focusOn(node) {
  focusNode = node;
  focusSet = new Set([node.id]);
  for (const e of edges) {
    if (e.source === node.id) focusSet.add(e.target);
    if (e.target === node.id) focusSet.add(e.source);
  }
  fitToNodes([...focusSet].map(id => byId.get(id)), 110, 2.4);
  userInteracted = true;
}
function clearFocus() {
  const had = !!focusNode;
  focusNode = null; focusSet = new Set();
  if (had) { fitView(); userInteracted = true; }  // solo reencuadra si había enfoque
}

// Nivel (fila) de un nodo, de arriba (perímetro/no confiable) hacia abajo
// (interno). Da una jerarquía legible tipo diagrama por capas.
const SERVER_ROLES = ['database', 'dns', 'web-server', 'mail-server',
                      'file-server', 'windows-server'];
function tierOf(n) {
  if (n.is_scanner || /extern/i.test(n.department || '')) return 0;  // perímetro
  if (SERVER_ROLES.includes(n.role)) return 1;                        // servidores
  return 2;                                                           // hosts/clientes
}

// Layout determinista por CAPAS: cada nivel es una fila; dentro de cada fila
// se ordenan los nodos para minimizar el cruce de líneas (heurística de
// baricentro). Es predecible y ordenado, sin depender de la física.
function organize() {
  clustered = false;
  for (const n of nodes) n.tier = tierOf(n);
  const tierVals = [...new Set(nodes.map(n => n.tier))].sort((a, b) => a - b);
  const rows = tierVals.map(t => nodes.filter(n => n.tier === t));

  // Adyacencia (para el baricentro).
  const adj = new Map(nodes.map(n => [n.id, []]));
  for (const e of edges) {
    if (adj.has(e.source)) adj.get(e.source).push(e.target);
    if (adj.has(e.target)) adj.get(e.target).push(e.source);
  }
  const bary = (n) => {
    const nb = adj.get(n.id) || [];
    let s = 0, c = 0;
    for (const id of nb) { const m = byId.get(id); if (m) { s += m.gx; c++; } }
    return c ? s / c : n.gx;
  };

  const padX = 70, padY = 90;
  const usableW = Math.max(1, W - padX * 2);
  const usableH = Math.max(1, H - padY * 2);
  const T = rows.length;
  const rowY = (ri) => padY + (T === 1 ? usableH / 2 : (usableH * ri) / (T - 1));
  const placeRow = (row, ri) => {
    const n = row.length, y = rowY(ri);
    row.forEach((node, i) => {
      node.gx = padX + (n === 1 ? usableW / 2 : (usableW * i) / (n - 1));
      node.gy = y;
    });
  };

  // Orden inicial por zona (agrupa mismas zonas), luego pasadas de baricentro.
  rows.forEach((row) => row.sort((a, b) =>
    (a.zone || '').localeCompare(b.zone || '') || (a.label || '').localeCompare(b.label || '')));
  rows.forEach(placeRow);
  for (let pass = 0; pass < 4; pass++) {
    rows.forEach((row, ri) => { row.sort((a, b) => bary(a) - bary(b)); placeRow(row, ri); });
  }

  // Fija posiciones: layout estático, sin física.
  for (const n of nodes) { n.x = n.gx; n.y = n.gy; n.vx = 0; n.vy = 0; n.fixed = true; }
  alpha = 0; fitted = false; userInteracted = false;
}

function onShow() {
  resize();
  // No cargamos automáticamente: el mapeo lo dispara el botón "Analizar red".
  // Así se respeta el flujo "ok, empecemos a analizar esta red".
  if (!running) { running = true; frame(); }
}

function stop() { running = false; if (raf) cancelAnimationFrame(raf); }

// --- Interacción: pan, zoom, hover y fijado de nodos ---
function relPos(e) {
  const rect = canvas.getBoundingClientRect();
  return { mx: e.clientX - rect.left, my: e.clientY - rect.top };
}
// Pantalla -> mundo (deshace la cámara), para picar/arrastrar nodos.
function toWorld(mx, my) {
  return { x: (mx - cam.x) / cam.scale, y: (my - cam.y) / cam.scale };
}
function pick(wx, wy) {
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    const dx = wx - n.x, dy = wy - n.y, r = n.r + 6;
    if (dx * dx + dy * dy <= r * r) return n;
  }
  return null;
}

canvas.addEventListener('mousemove', (e) => {
  const { mx, my } = relPos(e);

  // Con un botón presionado decidimos entre CLIC (enfocar) y ARRASTRE.
  if (press) {
    if (!press.moved && Math.hypot(mx - press.mx, my - press.my) > CLICK_MOVE) {
      press.moved = true;
    }
    if (press.moved) {
      tip.style.display = 'none';
      if (press.node) {
        dragNode = press.node; dragNode.fixed = true;   // mover y fijar el nodo
        const w = toWorld(mx, my); dragNode.x = w.x; dragNode.y = w.y;
      } else {
        cam.x += mx - press.mx; cam.y += my - press.my;  // pan del fondo
        press.mx = mx; press.my = my; userInteracted = true;
      }
      return;
    }
  }

  // Sin arrastre: hover + tooltip.
  const w = toWorld(mx, my);
  hoverNode = pick(w.x, w.y);
  if (hoverNode) {
    const n = hoverNode;
    const svc = (n.services || []).map(s => s.name).join(', ') || '—';
    tip.innerHTML =
      `<b>${n.label || n.ip}</b><span class="tip-ip">${n.ip}</span>`
      + `<div><span class="tip-k">rol</span> ${n.role}</div>`
      + (n.department ? `<div><span class="tip-k">zona</span> ${n.department}</div>` : '')
      + `<div><span class="tip-k">servicios</span> ${svc}</div>`
      + `<div><span class="tip-k">flujos</span> ${n.flows}</div>`
      + (n.is_scan_target ? `<div class="tip-warn">◈ objetivo de escaneo (${n.probed_ports} puertos)</div>` : '')
      + (n.is_scanner ? `<div class="tip-warn">◈ comportamiento de escáner</div>` : '')
      + `<div class="tip-hint">clic para ver sus relaciones</div>`;
    tip.style.display = 'block';
    tip.style.left = (mx + 14) + 'px';
    tip.style.top = (my + 14) + 'px';
    canvas.style.cursor = 'pointer';
  } else {
    tip.style.display = 'none';
    canvas.style.cursor = 'grab';
  }
});

canvas.addEventListener('mousedown', (e) => {
  const { mx, my } = relPos(e);
  const w = toWorld(mx, my);
  press = { mx, my, node: pick(w.x, w.y), moved: false };
  canvas.style.cursor = 'grabbing';
});

window.addEventListener('mouseup', () => {
  // Si no hubo movimiento, fue un clic: enfoca el nodo o limpia el enfoque.
  if (press && !press.moved) {
    if (press.node) focusOn(press.node);
    else clearFocus();
  }
  dragNode = null; press = null;
  canvas.style.cursor = 'grab';
});
canvas.addEventListener('mouseleave', () => { tip.style.display = 'none'; });

// Rueda del ratón = zoom centrado en el cursor.
canvas.addEventListener('wheel', (e) => {
  e.preventDefault();
  const { mx, my } = relPos(e);
  const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
  const ns = Math.max(0.2, Math.min(4, cam.scale * factor));
  // Mantiene fijo el punto de mundo bajo el cursor al hacer zoom.
  const wx = (mx - cam.x) / cam.scale, wy = (my - cam.y) / cam.scale;
  cam.scale = ns;
  cam.x = mx - wx * ns; cam.y = my - wy * ns;
  userInteracted = true;
}, { passive: false });

// Doble clic: sobre un nodo lo libera (vuelve a fluir); sobre el vacío,
// reorganiza y reencuadra todo el grafo desde cero.
canvas.addEventListener('dblclick', (e) => {
  const { mx, my } = relPos(e);
  const w = toWorld(mx, my);
  const n = pick(w.x, w.y);
  if (n) focusOn(n);
  else { clearFocus(); organize(); }   // doble clic en vacío = reorganizar
});

// Botón "Analizar red": dispara el mapeo (descubre + dibuja la topología real).
const analyzeBtn = document.getElementById('map-analyze');
if (analyzeBtn) analyzeBtn.addEventListener('click', async () => {
  statusEl.textContent = 'analizando la red…';
  await load();   // fetch /api/discovery + organize()
});

// Botón "Organizar": reacomodo automático agrupado (relayout).
const organizeBtn = document.getElementById('map-organize');
if (organizeBtn) organizeBtn.addEventListener('click', () => organize());

// --- Ciclo de vida atado a la conmutación de vistas ---
// La vista de red usa el id "centinela" (era la principal); arranca al mostrarse
// y se pausa en otras vistas para no gastar CPU.
document.addEventListener('viewchange', (e) => {
  if (e.detail.id === 'centinela') onShow();
  else stop();
});
window.addEventListener('resize', () => {
  if (running) resize();
});

// La vista de red es la principal (activa por defecto): arrancamos el lienzo al
// cargar, tras el layout, para que muestre el estado vacío con su llamada a
// "Analizar red". No hay evento viewchange en la carga inicial.
if (document.querySelector('.view-centinela.active')) {
  requestAnimationFrame(onShow);
}
