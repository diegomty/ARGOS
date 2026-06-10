// Capa de topología: convierte el JSON de /api/topology en geometría 3D
// (nodos como mallas + etiquetas CSS2D) que vive dentro del icosaedro.
//
// El layout es radial determinista — los departamentos forman un anillo,
// cada host orbita su departamento, y la zona externa queda al "norte"
// fuera de la membrana.

import * as THREE from 'three';
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';

// --- Geometrías por tipo (creadas una sola vez y reutilizadas) ---
const GEOMETRY = {
  sentinel:   new THREE.IcosahedronGeometry(0.10, 1),
  router:     new THREE.OctahedronGeometry(0.11, 0),
  switch:     new THREE.BoxGeometry(0.16, 0.05, 0.16),
  department: new THREE.BoxGeometry(0.18, 0.18, 0.18),
  host:       new THREE.BoxGeometry(0.07, 0.07, 0.07),
  external:   new THREE.IcosahedronGeometry(0.13, 0),
};

// Color por defecto cuando el nodo no trae `metadata.color_hint`.
const FALLBACK_COLOR = {
  sentinel:   0xffffff,
  router:     0x5ee0d6,
  switch:     0x6c7a99,
  department: 0xf5c14b,
  host:       0xb8c4d6,
  external:   0xff4d6d,
};

// Solo etiquetamos los nodos que el operador necesita identificar a
// distancia. Hosts permanecen sin label para evitar saturar la vista.
const LABELED_TYPES = new Set(['sentinel', 'router', 'department', 'external']);
const LABELED_IDS   = new Set(['attacker']);

// --- Estilos de los enlaces por tipo ---
//   trunk:    R1 ↔ SW1, backbone que carga las 6 VLANs (dot1q)
//   access:   capilar (SW1 → depto, depto → host)
//   external: perímetro hacia la zona untrusted
//   mgmt:     SSH/syslog del Sentinel al router
const LINK_STYLE = {
  trunk:    { color: 0x5ee0d6, radius: 0.012, opacity: 0.75 },
  access:   { color: 0x6c7a99, radius: 0.005, opacity: 0.45 },
  external: { color: 0xff4d6d, radius: 0.009, opacity: 0.65 },
  mgmt:     { color: 0xa78bfa, radius: 0.006, opacity: 0.55 },
};

// --- Color de la partícula según protocolo IANA ---
const FLOW_COLOR = {
  icmp: 0xfb923c,   // naranja — recon / control
  tcp:  0x5ee0d6,   // cyan — datos confiables
  udp:  0xa78bfa,   // morado — datos best-effort
};
const FLOW_DEFAULT_COLOR = 0x6c7a99;
const FLOW_DURATION_S    = 1.6;
const FLOW_PARTICLE_GEOM = new THREE.SphereGeometry(0.055, 12, 12);

export function buildTopology(topology) {
  const group = new THREE.Group();
  group.name = 'topology';

  const positions = computeLayout(topology);
  const nodeMeshes = new Map();

  for (const node of topology.nodes) {
    const pos = positions.get(node.id);
    if (!pos) continue;

    const colorHex = node.metadata?.color_hint
      ? new THREE.Color(node.metadata.color_hint).getHex()
      : FALLBACK_COLOR[node.type] ?? 0xffffff;

    const mat = new THREE.MeshStandardMaterial({
      color: colorHex,
      emissive: colorHex,
      emissiveIntensity: node.type === 'sentinel' ? 0.9 : 0.5,
      metalness: 0.3,
      roughness: 0.45,
    });

    const mesh = new THREE.Mesh(GEOMETRY[node.type] ?? GEOMETRY.host, mat);
    mesh.position.copy(pos);
    // Guardamos los originales del material para poder restaurarlos
    // cuando un nodo deja de estar aislado (estado isolated → activo).
    mesh.userData = {
      node,
      originalColor: mat.color.clone(),
      originalEmissive: mat.emissive.clone(),
      originalEmissiveIntensity: mat.emissiveIntensity,
    };

    if (LABELED_TYPES.has(node.type) || LABELED_IDS.has(node.id)) {
      const label = makeLabel(node);
      label.position.set(0, geometricRadius(node.type) + 0.08, 0);
      mesh.add(label);
    }

    nodeMeshes.set(node.id, mesh);
    group.add(mesh);
  }

  // --- Enlaces (tubos curvos entre nodos) ---
  const linkMeshes = buildLinks(topology, positions, group);

  // --- Paths para animación de flujos ---
  // Pre-computamos la curva entre cada par (src_node, dst_node) que pueda
  // generar tráfico, pasando por sw1 (dept↔dept) o r1 (dept↔external).
  const flowPaths = computeFlowPaths(topology, positions);

  // Pool de partículas activas — { mesh, progress, duration, curve }
  const particles = [];

  // Iluminación local — los MeshStandardMaterial necesitan luz para
  // mostrar matices. Una key + ambient suaves bastan.
  const ambient = new THREE.AmbientLight(0xffffff, 0.55);
  const key = new THREE.DirectionalLight(0xffffff, 0.7);
  key.position.set(2, 3, 2);
  group.add(ambient, key);

  // Conjunto mutable de node_ids aislados — main.js lo actualiza con
  // los mensajes `topology_state` que llegan por WebSocket.
  const isolatedSet = new Set();

  function spawnFlow(flow) {
    const key = `${flow.src_node}->${flow.dst_node}`;
    const curve = flowPaths.get(key);
    if (!curve) {
      console.warn('[flow] sin path para', key, '· paths conocidos:', flowPaths.size);
      return;
    }
    // Veredicto del detector híbrido (flow.ml viene del servidor): los
    // flujos marcados viajan en rojo, más grandes y más lentos para que
    // el ojo del operador los capture entre el tráfico normal.
    const flagged = !!flow.ml?.is_anomaly;
    const colorHex = flagged
      ? 0xff4d6d
      : (FLOW_COLOR[flow.protocol] ?? FLOW_DEFAULT_COLOR);
    const mat = new THREE.MeshBasicMaterial({
      color: colorHex,
      transparent: true,
      opacity: 0.0,                 // sube en el fade-in
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });
    const mesh = new THREE.Mesh(FLOW_PARTICLE_GEOM, mat);
    if (flagged) mesh.scale.setScalar(1.7);
    // renderOrder alto: las partículas se dibujan DESPUÉS de la membrana,
    // así nunca quedan atenuadas por la transparencia del icosaedro.
    mesh.renderOrder = 20;
    group.add(mesh);
    particles.push({
      mesh, curve, progress: 0,
      duration: flagged ? FLOW_DURATION_S * 1.6 : FLOW_DURATION_S,
    });
  }

  return {
    group,
    nodeMeshes,
    linkMeshes,
    isolatedSet,
    setIsolated(nodeIds) {
      isolatedSet.clear();
      for (const id of nodeIds) isolatedSet.add(id);
    },
    spawnFlow,
    update(state, dt, t) {
      const breathe = 1 + state.pulse * 0.18;
      const isolatedPulse = 0.55 + Math.sin(t * 4.0) * 0.35;  // halo rojo pulsante

      for (const [id, m] of nodeMeshes) {
        const node = m.userData.node;
        const isolated = isolatedSet.has(id);

        // --- Material: tinte gris + halo rojo cuando aislado, original cuando no ---
        if (isolated) {
          m.material.color.setHex(0x303040);
          m.material.emissive.setHex(0xff4d6d);
          m.material.emissiveIntensity = isolatedPulse;
        } else {
          m.material.color.copy(m.userData.originalColor);
          m.material.emissive.copy(m.userData.originalEmissive);
          m.material.emissiveIntensity = m.userData.originalEmissiveIntensity;
        }

        // --- Escala: respiración por anomalía + encogimiento por aislamiento ---
        let scale = 1;
        if (node.type === 'department') scale *= breathe;
        if (isolated) scale *= 0.8;
        m.scale.setScalar(scale);

        m.rotation.y += dt * 0.25;
      }

      // --- Links: rojos pulsantes si tocan un nodo aislado, originales si no ---
      for (const lm of linkMeshes) {
        const link = lm.userData.link;
        const cut = isolatedSet.has(link.source) || isolatedSet.has(link.target);
        if (cut) {
          lm.material.color.setHex(0xff4d6d);
          lm.material.opacity = 0.25 + Math.sin(t * 3.0) * 0.20;
        } else if (link.type === 'external') {
          // Pulso del enlace perimetral durante bloqueos automáticos.
          lm.material.color.copy(lm.userData.originalColor);
          lm.material.opacity = lm.userData.originalOpacity + state.blockPulse * 0.4;
        } else {
          lm.material.color.copy(lm.userData.originalColor);
          lm.material.opacity = lm.userData.originalOpacity;
        }
      }

      // --- Partículas de flujos NetFlow ---
      // Avanzan a velocidad constante a lo largo de su curva. Fade in
      // al inicio, fade out al final, eliminamos al completar.
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.progress += dt / p.duration;
        if (p.progress >= 1) {
          group.remove(p.mesh);
          p.mesh.material.dispose();
          particles.splice(i, 1);
          continue;
        }
        const pos = p.curve.getPointAt(p.progress);
        p.mesh.position.copy(pos);
        // Bell-shaped opacity: 0 → 0.95 → 0 con pico al 50%
        p.mesh.material.opacity = Math.sin(p.progress * Math.PI) * 0.95;
      }
    },
  };
}

// Pre-computa una curva CatmullRom entre cada par (src, dst) de nodos
// que pueden generar tráfico. dept↔dept pasa por sw1, dept↔external por r1.
// Resultado: un Map<"src->dst", THREE.CatmullRomCurve3>.
function computeFlowPaths(topology, positions) {
  const paths = new Map();
  const sw = topology.nodes.find(n => n.type === 'switch');
  const r1 = topology.nodes.find(n => n.type === 'router');
  const swPos = sw ? positions.get(sw.id) : null;
  const r1Pos = r1 ? positions.get(r1.id) : null;

  const endpoints = topology.nodes.filter(
    n => n.type === 'department' || n.type === 'external'
  );

  for (const src of endpoints) {
    for (const dst of endpoints) {
      if (src.id === dst.id) continue;
      const a = positions.get(src.id);
      const b = positions.get(dst.id);
      if (!a || !b) continue;

      // Ruta lógica: traffic between two depts goes through SW1; traffic
      // to/from external zone goes through R1.
      let waypoints;
      if (src.type === 'department' && dst.type === 'department' && swPos) {
        waypoints = [a, swPos.clone().lerp(a, 0.2), swPos, swPos.clone().lerp(b, 0.2), b];
      } else if (r1Pos) {
        waypoints = [a, r1Pos.clone().lerp(a, 0.2), r1Pos, r1Pos.clone().lerp(b, 0.2), b];
      } else {
        waypoints = [a, b];
      }
      const curve = new THREE.CatmullRomCurve3(waypoints, false, 'catmullrom', 0.5);
      paths.set(`${src.id}->${dst.id}`, curve);
    }
  }
  return paths;
}

function buildLinks(topology, positions, group) {
  const meshes = [];
  for (const link of topology.links) {
    const a = positions.get(link.source);
    const b = positions.get(link.target);
    if (!a || !b) continue;

    // Punto de control del Bezier: punto medio empujado ligeramente
    // hacia el origen → curvas que "abrazan" el núcleo, evitando que
    // múltiples links solapen en línea recta.
    const mid = a.clone().add(b).multiplyScalar(0.5);
    const towardCenter = mid.clone().multiplyScalar(-0.18);
    const control = mid.clone().add(towardCenter);

    const curve = new THREE.QuadraticBezierCurve3(a, control, b);
    const style = LINK_STYLE[link.type] ?? LINK_STYLE.access;

    // 32 segmentos longitudinales, 6 radiales — suave sin pasarse
    // de polígonos (16 links * 32 * 6 ≈ 3k tris totales, irrelevante).
    const tubeGeo = new THREE.TubeGeometry(curve, 32, style.radius, 6, false);
    const mat = new THREE.MeshBasicMaterial({
      color: style.color,
      transparent: true,
      opacity: style.opacity,
      depthWrite: false,
    });

    const mesh = new THREE.Mesh(tubeGeo, mat);
    mesh.userData = {
      link,
      originalColor: new THREE.Color(style.color),
      originalOpacity: style.opacity,
    };
    meshes.push(mesh);
    group.add(mesh);
  }
  return meshes;
}

function geometricRadius(type) {
  switch (type) {
    case 'department': return 0.10;
    case 'router':     return 0.08;
    case 'sentinel':   return 0.08;
    case 'external':   return 0.10;
    default:           return 0.05;
  }
}

function makeLabel(node) {
  const div = document.createElement('div');
  div.className = 'node-label node-label-' + node.type;
  div.textContent = node.label;
  if (node.subnet) {
    const sub = document.createElement('div');
    sub.className = 'node-label-sub';
    sub.textContent = node.subnet + (node.vlan ? `  VLAN ${node.vlan}` : '');
    div.appendChild(sub);
  }
  return new CSS2DObject(div);
}

// ---------- Layout radial determinista ----------

function computeLayout(topology) {
  const positions = new Map();

  // 1) Posiciones declaradas explícitamente en el YAML tienen prioridad.
  for (const node of topology.nodes) {
    if (Array.isArray(node.position) && node.position.length === 3) {
      positions.set(node.id, new THREE.Vector3(...node.position));
    }
  }

  // 2) Departamentos en un anillo horizontal centrado en el origen.
  const depts = topology.nodes.filter(n => n.type === 'department');
  const DEPT_RADIUS = 0.95;
  for (let i = 0; i < depts.length; i++) {
    if (positions.has(depts[i].id)) continue;
    const angle = (i / depts.length) * Math.PI * 2;
    positions.set(depts[i].id, new THREE.Vector3(
      Math.cos(angle) * DEPT_RADIUS,
      Math.sin(i * 1.3) * 0.08,   // ondulación sutil para que no parezca un disco plano
      Math.sin(angle) * DEPT_RADIUS,
    ));
  }

  // 3) Hosts radian hacia afuera desde su departamento padre.
  const hostsByParent = new Map();
  for (const n of topology.nodes) {
    if (n.type !== 'host' || !n.parent) continue;
    if (!hostsByParent.has(n.parent)) hostsByParent.set(n.parent, []);
    hostsByParent.get(n.parent).push(n);
  }
  const HOST_OFFSET = 0.32;
  for (const [parentId, kids] of hostsByParent) {
    const parentPos = positions.get(parentId);
    if (!parentPos) continue;
    const outward = parentPos.clone().normalize();
    const tangent = new THREE.Vector3(-outward.z, 0, outward.x).normalize();
    for (let i = 0; i < kids.length; i++) {
      if (positions.has(kids[i].id)) continue;
      const lateral = (i - (kids.length - 1) / 2) * 0.16;
      const p = parentPos.clone()
        .add(outward.clone().multiplyScalar(HOST_OFFSET))
        .add(tangent.clone().multiplyScalar(lateral));
      positions.set(kids[i].id, p);
    }
  }

  // 4) Núcleo: router y switch alrededor del sentinel.
  const router = topology.nodes.find(n => n.type === 'router');
  if (router && !positions.has(router.id)) {
    positions.set(router.id, new THREE.Vector3(0.35, 0.05, 0));
  }
  const sw = topology.nodes.find(n => n.type === 'switch');
  if (sw && !positions.has(sw.id)) {
    positions.set(sw.id, new THREE.Vector3(-0.35, -0.05, 0));
  }

  // 5) Zona externa por encima de la membrana, atacante aún más arriba.
  const ext = topology.nodes.find(n => n.type === 'external');
  if (ext && !positions.has(ext.id)) {
    positions.set(ext.id, new THREE.Vector3(0, 1.10, 0));
  }
  const attacker = topology.nodes.find(n => n.id === 'attacker');
  if (attacker && !positions.has(attacker.id)) {
    positions.set(attacker.id, new THREE.Vector3(0, 1.40, 0));
  }

  return positions;
}
