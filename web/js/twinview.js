// Vista "Gemelo Digital": representación 3D de la red real descubierta.
//
// A diferencia del twin viejo (una membrana deformada por ruido que se
// estiraba, alimentada por la topología FIJA del lab), este es un GLOBO DE
// ALAMBRE ESTABLE — geometría rígida, sin displacement — dentro del cual
// orbitan los dispositivos REALES de /api/discovery (los mismos del Mapa).
//
// Reacción automática: cada evento de amenaza (qs:event, p. ej. un hit del
// honeypot) trae la IP atacante; localizamos ese nodo y lo hacemos PULSAR en
// rojo con una onda de choque. Si la IP no es un nodo conocido, materializamos
// un "intruso" en el perímetro. Así el gemelo late con la actividad real.
//
// Ciclo de vida: solo renderiza mientras la vista está activa (evento
// `viewchange`), con DPR limitado y resize por ResizeObserver — las causas del
// "desplazamiento" de antes quedan controladas.

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

const wrap = document.getElementById('twin-wrap');
const statusEl = document.getElementById('twin-status');
const emptyEl = document.getElementById('twin-empty');

// Color por rol (mismos tonos que el Mapa 2D, en hex numérico para three).
const ROLE_COLOR = {
  database: 0xf5c14b, dns: 0xa78bfa, 'windows-server': 0x5ee0d6,
  'mail-server': 0x60a5fa, 'web-server': 0x7cf09a, 'file-server': 0xf59e0b,
  'ssh-host': 0x94a3b8, scanner: 0xff4d6d, workstation: 0xb8c4d6,
  host: 0x6c7a99, internet: 0x64748b,
};
const RED = 0xff4d6d;
const GLOBE_R = 5;            // radio del globo de alambre
const NODE_BASE = 0.14;       // radio base de un nodo

let scene, camera, renderer, controls, raycaster, pointer;
let globe, nodeGroup, edgeGroup, fxGroup;
let tip;
let running = false, inited = false, loaded = false, raf = null;
let ro = null;
const nodes = new Map();      // ip -> { mesh, halo, baseColor, pulseUntil }
const shockwaves = [];        // ondas de choque activas

// --- Inicialización (una sola vez) ---------------------------------------
function init() {
  if (inited) return;
  const w = wrap.clientWidth || 800, h = wrap.clientHeight || 600;

  scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x070b14, 0.045);

  camera = new THREE.PerspectiveCamera(55, w / h, 0.1, 100);
  camera.position.set(0, 2, 14);

  renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(w, h);
  renderer.setClearColor(0x070b14, 0);
  wrap.appendChild(renderer.domElement);

  controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.5;   // giro lento, sensación "vivo" sin marear
  controls.minDistance = 7;
  controls.maxDistance = 30;

  scene.add(new THREE.AmbientLight(0x8899bb, 0.9));
  const key = new THREE.PointLight(0x5ee0d6, 1.1, 60);
  key.position.set(8, 10, 12);
  scene.add(key);

  // Globo de alambre ESTÁTICO (icosaedro subdividido) — la "cáscara".
  const shell = new THREE.IcosahedronGeometry(GLOBE_R, 3);
  globe = new THREE.LineSegments(
    new THREE.WireframeGeometry(shell),
    new THREE.LineBasicMaterial({ color: 0x1f2a44, transparent: true, opacity: 0.5 }),
  );
  scene.add(globe);

  nodeGroup = new THREE.Group();
  edgeGroup = new THREE.Group();
  fxGroup = new THREE.Group();
  scene.add(nodeGroup, edgeGroup, fxGroup);

  raycaster = new THREE.Raycaster();
  pointer = new THREE.Vector2(-2, -2);

  tip = document.createElement('div');
  tip.className = 'map-tip';
  tip.style.display = 'none';
  wrap.appendChild(tip);

  renderer.domElement.addEventListener('mousemove', onMove);
  renderer.domElement.addEventListener('mouseleave', () => { tip.style.display = 'none'; });

  ro = new ResizeObserver(() => resize());
  ro.observe(wrap);

  inited = true;
}

function resize() {
  if (!inited) return;
  const w = wrap.clientWidth, h = wrap.clientHeight;
  if (!w || !h) return;
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
  renderer.setSize(w, h);
}

// --- Distribución de nodos en esfera (Fibonacci: reparto uniforme) --------
function fibSphere(i, n, r) {
  const phi = Math.acos(1 - 2 * (i + 0.5) / n);
  const theta = Math.PI * (1 + Math.sqrt(5)) * i;
  return new THREE.Vector3(
    r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta),
  );
}

function makeNode(n, pos) {
  const color = ROLE_COLOR[n.role] || ROLE_COLOR.host;
  const size = NODE_BASE + Math.min(0.22, Math.log2((n.flows || 1) + 1) * 0.03);
  const mesh = new THREE.Mesh(
    new THREE.SphereGeometry(size, 20, 20),
    new THREE.MeshStandardMaterial({
      color, emissive: color, emissiveIntensity: 0.6, roughness: 0.4,
    }),
  );
  mesh.position.copy(pos);
  mesh.userData = { ip: n.ip, node: n, size };
  // Halo suave (esfera translúcida additiva).
  const halo = new THREE.Mesh(
    new THREE.SphereGeometry(size * 2.2, 16, 16),
    new THREE.MeshBasicMaterial({
      color, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending,
    }),
  );
  mesh.add(halo);
  nodeGroup.add(mesh);
  nodes.set(n.ip, { mesh, halo, baseColor: color, pulseUntil: 0 });
  return mesh;
}

async function loadNetwork() {
  try {
    const mf = localStorage.getItem('qs_min_flows') || '2';
    const g = await fetch(`/api/discovery?min_flows=${encodeURIComponent(mf)}`).then(r => r.json());

    nodeGroup.clear(); edgeGroup.clear(); nodes.clear();
    const list = g.nodes || [];
    list.forEach((n, i) => makeNode(n, fibSphere(i, list.length, GLOBE_R * 0.82)));

    // Aristas como líneas tenues entre nodos conocidos.
    const mat = new THREE.LineBasicMaterial({ color: 0x2f7d78, transparent: true, opacity: 0.28 });
    for (const e of (g.edges || [])) {
      const a = nodes.get(e.source), b = nodes.get(e.target);
      if (!a || !b) continue;
      const geo = new THREE.BufferGeometry().setFromPoints([a.mesh.position, b.mesh.position]);
      edgeGroup.add(new THREE.Line(geo, mat));
    }

    loaded = true;
    emptyEl.style.display = 'none';
    const s = g.stats || {};
    statusEl.textContent =
      `${s.node_count || list.length} dispositivos · ${s.edge_count || 0} relaciones · `
      + `arrastra: orbitar · rueda: zoom`;
  } catch (err) {
    statusEl.textContent = 'no se pudo cargar la red';
    emptyEl.textContent = 'Error construyendo el gemelo: ' + err;
    emptyEl.style.display = 'flex';
  }
}

// --- Reacción a amenazas -------------------------------------------------
function spawnIntruder(ip) {
  // Nodo rojo en el "norte" del globo, fuera de la cáscara.
  const pos = new THREE.Vector3(0, GLOBE_R * 1.25, 0);
  const mesh = new THREE.Mesh(
    new THREE.SphereGeometry(0.22, 20, 20),
    new THREE.MeshStandardMaterial({ color: RED, emissive: RED, emissiveIntensity: 0.9 }),
  );
  mesh.position.copy(pos);
  mesh.userData = { ip, node: { ip, role: 'intruso', label: ip }, size: 0.22 };
  nodeGroup.add(mesh);
  nodes.set(ip, { mesh, halo: null, baseColor: RED, pulseUntil: 0 });
  return nodes.get(ip);
}

function reactTo(ip) {
  if (!ip) return;
  let rec = nodes.get(ip);
  if (!rec) { if (!loaded) return; rec = spawnIntruder(ip); }
  rec.pulseUntil = performance.now() + 2200;   // pulsa ~2.2 s
  // Onda de choque: anillo que se expande y se desvanece.
  const ring = new THREE.Mesh(
    new THREE.RingGeometry(0.2, 0.28, 32),
    new THREE.MeshBasicMaterial({
      color: RED, transparent: true, opacity: 0.9, side: THREE.DoubleSide,
      blending: THREE.AdditiveBlending, depthWrite: false,
    }),
  );
  ring.position.copy(rec.mesh.position);
  fxGroup.add(ring);
  shockwaves.push({ ring, start: performance.now() });
}

// --- Interacción: hover con tooltip --------------------------------------
function onMove(e) {
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const hit = raycaster.intersectObjects(nodeGroup.children, false)[0];
  if (hit) {
    const n = hit.object.userData.node || {};
    tip.innerHTML =
      `<b>${n.device_name || n.label || n.ip}</b><span class="tip-ip">${n.ip || ''}</span>`
      + `<div><span class="tip-k">rol</span> ${n.role || '—'}</div>`
      + (n.vendor ? `<div><span class="tip-k">fabricante</span> ${n.vendor}</div>` : '')
      + (n.flows != null ? `<div><span class="tip-k">flujos</span> ${n.flows}</div>` : '');
    tip.style.display = 'block';
    tip.style.left = (e.clientX - rect.left + 14) + 'px';
    tip.style.top = (e.clientY - rect.top + 14) + 'px';
    renderer.domElement.style.cursor = 'pointer';
  } else {
    tip.style.display = 'none';
    renderer.domElement.style.cursor = 'grab';
  }
}

// --- Bucle de render -----------------------------------------------------
function frame() {
  if (!running) return;
  const now = performance.now();

  // Pulso de nodos atacados: escala + emisivo laten, color hacia rojo.
  for (const rec of nodes.values()) {
    if (now < rec.pulseUntil) {
      const k = 1 + 0.5 * Math.abs(Math.sin(now * 0.012));
      rec.mesh.scale.setScalar(k);
      rec.mesh.material.emissiveIntensity = 1.4;
      rec.mesh.material.emissive.setHex(RED);
      rec.mesh.material.color.setHex(RED);
    } else if (rec.mesh.scale.x !== 1) {
      rec.mesh.scale.setScalar(1);
      rec.mesh.material.emissiveIntensity = 0.6;
      rec.mesh.material.emissive.setHex(rec.baseColor);
      rec.mesh.material.color.setHex(rec.baseColor);
    }
  }

  // Ondas de choque: crecen y se desvanecen, luego se eliminan.
  for (let i = shockwaves.length - 1; i >= 0; i--) {
    const sw = shockwaves[i];
    const t = (now - sw.start) / 1000;      // 0..1 en ~1 s
    if (t >= 1) { fxGroup.remove(sw.ring); sw.ring.geometry.dispose(); sw.ring.material.dispose(); shockwaves.splice(i, 1); continue; }
    sw.ring.scale.setScalar(1 + t * 8);
    sw.ring.material.opacity = 0.9 * (1 - t);
    sw.ring.lookAt(camera.position);        // siempre de cara a la cámara
  }

  controls.update();
  renderer.render(scene, camera);
  raf = requestAnimationFrame(frame);
}

// --- Ciclo de vida atado a la conmutación de vistas ----------------------
function onShow() {
  init();
  resize();
  if (!loaded) { emptyEl.style.display = 'flex'; loadNetwork(); }
  if (!running) { running = true; frame(); }
}
function stop() { running = false; if (raf) cancelAnimationFrame(raf); raf = null; }

document.addEventListener('viewchange', (e) => {
  if (e.detail.id === 'gemelo') onShow();
  else stop();
});

// Reacción en vivo: cualquier evento de amenaza hace latir su nodo.
document.addEventListener('qs:event', (e) => {
  const ev = e.detail;
  if (ev && ev.is_anomaly) reactTo(ev.attacker_ip || ev.source_ip);
});

// Botón "Actualizar": recarga los dispositivos.
const reloadBtn = document.getElementById('twin-reload');
if (reloadBtn) reloadBtn.addEventListener('click', () => loadNetwork());
