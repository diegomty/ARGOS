import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { CSS2DRenderer } from 'three/addons/renderers/CSS2DRenderer.js';
import { buildTopology } from './topologyLayer.js';

// Stefan Gustavson 3D simplex noise — implementación canónica.
// Reutilizada en VS y FS si hace falta; aquí solo en VS para displacement.
const NOISE_GLSL = /* glsl */`
  vec3 mod289(vec3 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
  vec4 mod289(vec4 x) { return x - floor(x * (1.0/289.0)) * 289.0; }
  vec4 permute(vec4 x) { return mod289(((x * 34.0) + 1.0) * x); }
  vec4 taylorInvSqrt(vec4 r) { return 1.79284291400159 - 0.85373472095314 * r; }
  float snoise(vec3 v) {
    const vec2 C = vec2(1.0/6.0, 1.0/3.0);
    const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
    vec3 i  = floor(v + dot(v, C.yyy));
    vec3 x0 = v - i + dot(i, C.xxx);
    vec3 g  = step(x0.yzx, x0.xyz);
    vec3 l  = 1.0 - g;
    vec3 i1 = min(g.xyz, l.zxy);
    vec3 i2 = max(g.xyz, l.zxy);
    vec3 x1 = x0 - i1 + C.xxx;
    vec3 x2 = x0 - i2 + C.yyy;
    vec3 x3 = x0 - D.yyy;
    i = mod289(i);
    vec4 p = permute(permute(permute(
              i.z + vec4(0.0, i1.z, i2.z, 1.0))
            + i.y + vec4(0.0, i1.y, i2.y, 1.0))
            + i.x + vec4(0.0, i1.x, i2.x, 1.0));
    float n_ = 0.142857142857;
    vec3 ns = n_ * D.wyz - D.xzx;
    vec4 j  = p - 49.0 * floor(p * ns.z * ns.z);
    vec4 x_ = floor(j * ns.z);
    vec4 y_ = floor(j - 7.0 * x_);
    vec4 x  = x_ * ns.x + ns.yyyy;
    vec4 y  = y_ * ns.x + ns.yyyy;
    vec4 h  = 1.0 - abs(x) - abs(y);
    vec4 b0 = vec4(x.xy, y.xy);
    vec4 b1 = vec4(x.zw, y.zw);
    vec4 s0 = floor(b0) * 2.0 + 1.0;
    vec4 s1 = floor(b1) * 2.0 + 1.0;
    vec4 sh = -step(h, vec4(0.0));
    vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
    vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
    vec3 p0 = vec3(a0.xy, h.x);
    vec3 p1 = vec3(a0.zw, h.y);
    vec3 p2 = vec3(a1.xy, h.z);
    vec3 p3 = vec3(a1.zw, h.w);
    vec4 norm = taylorInvSqrt(vec4(dot(p0, p0), dot(p1, p1), dot(p2, p2), dot(p3, p3)));
    p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
    vec4 m = max(0.6 - vec4(dot(x0, x0), dot(x1, x1), dot(x2, x2), dot(x3, x3)), 0.0);
    m = m * m;
    return 42.0 * dot(m * m, vec4(dot(p0, x0), dot(p1, x1), dot(p2, x2), dot(p3, x3)));
  }
`;

const VS = NOISE_GLSL + /* glsl */`
  uniform float uTime;
  uniform float uH;
  uniform float uPulse;
  uniform float uBlockPulse;
  uniform vec3  uAttackOrigin;

  varying float vDisp;
  varying vec3  vNormal;
  varying vec3  vViewPos;

  void main() {
    vec3 p = position;

    // Intensidad del caos = entropía normalizada + pulso de anomalía.
    float intensity = clamp((uH - 3.0) / 2.5, 0.0, 1.5) + uPulse * 0.6;

    // Dos octavas de simplex 3D para textura visual rica.
    float n  = snoise(p * 1.2 + vec3(uTime * 0.25));
    float n2 = snoise(p * 2.8 + vec3(uTime * 0.55)) * 0.45;
    float disp = (n + n2) * intensity * 0.35;

    // Onda de choque desde la dirección del atacante en bloqueo.
    float dirDot = dot(normalize(p), normalize(uAttackOrigin));
    float shock = uBlockPulse * smoothstep(0.5, 1.0, dirDot) * 0.5;

    p += normal * (disp + shock);

    vDisp = disp + shock;
    vNormal = normalize(normalMatrix * normal);
    vec4 mv = modelViewMatrix * vec4(p, 1.0);
    vViewPos = mv.xyz;
    gl_Position = projectionMatrix * mv;
  }
`;

const FS = /* glsl */`
  uniform float uH;
  uniform float uPulse;
  varying float vDisp;
  varying vec3  vNormal;
  varying vec3  vViewPos;

  vec3 colorForH(float h) {
    vec3 cian  = vec3(0.37, 0.88, 0.84);
    vec3 amber = vec3(0.96, 0.76, 0.29);
    vec3 red   = vec3(1.00, 0.30, 0.43);
    if (h < 4.5) return mix(cian, amber, smoothstep(3.0, 4.5, h));
    return mix(amber, red, smoothstep(5.0, 5.5, h));
  }

  void main() {
    vec3 base = colorForH(uH);

    // Las crestas (vDisp positivo grande) se iluminan más; las grietas
    // se oscurecen. Da textura sin tener que muestrear normales.
    float ridge = clamp(vDisp * 1.5, -0.4, 0.6);
    vec3 col = base * (1.0 + ridge * 1.3);

    // Fresnel: el borde brilla más, efecto de "globo de datos".
    vec3 viewDir = normalize(-vViewPos);
    float fres = pow(1.0 - max(dot(vNormal, viewDir), 0.0), 2.5);
    col += base * fres * 0.7;

    // Flash blanco breve durante anomalía
    col += vec3(uPulse * 0.25);

    // La membrana es semi-transparente para dejar ver la topología
    // interna; se vuelve más opaca durante anomalías para reforzar el
    // efecto de "encierro".
    float alpha = 0.32 + uPulse * 0.35 + fres * 0.25;
    gl_FragColor = vec4(col, alpha);
  }
`;

export class MeshView {
  constructor(canvas) {
    this.canvas = canvas;
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x070b14);

    this.camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
    this.camera.position.set(0, 0, 4.5);

    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    this.controls = new OrbitControls(this.camera, canvas);
    this.controls.enableDamping = true;
    this.controls.enablePan = false;
    this.controls.minDistance = 2.5;
    this.controls.maxDistance = 8;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 0.5;

    // 5 subdivisiones → 5120 triángulos, suficiente para displacement suave.
    const geom = new THREE.IcosahedronGeometry(1.5, 5);

    this.uniforms = {
      uTime:         { value: 0 },
      uH:            { value: 3.0 },
      uPulse:        { value: 0 },
      uBlockPulse:   { value: 0 },
      uAttackOrigin: { value: new THREE.Vector3(0, 0, 1) },
    };

    this.material = new THREE.ShaderMaterial({
      uniforms: this.uniforms,
      vertexShader: VS,
      fragmentShader: FS,
      transparent: true,
      depthWrite: false,
      side: THREE.DoubleSide,
    });

    this.mesh = new THREE.Mesh(geom, this.material);
    // renderOrder alto: la membrana se dibuja después de los nodos
    // internos, garantizando que los nodos no queden "tapados" por la
    // transparencia con z-fighting raros.
    this.mesh.renderOrder = 10;
    this.scene.add(this.mesh);

    // Wireframe sutil superpuesto refuerza el aspecto "técnico".
    const wire = new THREE.Mesh(
      new THREE.IcosahedronGeometry(1.51, 2),
      new THREE.MeshBasicMaterial({
        color: 0x1f2a44,
        wireframe: true,
        transparent: true,
        opacity: 0.35,
      }),
    );
    this.scene.add(wire);
    this.wire = wire;

    // --- Renderer auxiliar para etiquetas HTML (CSS2D) ---
    // Sus elementos viven en un <div> absolutamente posicionado sobre
    // el canvas WebGL. Se renderiza después de cada frame.
    this.labelRenderer = new CSS2DRenderer();
    this.labelRenderer.domElement.style.position = 'absolute';
    this.labelRenderer.domElement.style.top = '0';
    this.labelRenderer.domElement.style.left = '0';
    this.labelRenderer.domElement.style.pointerEvents = 'none';
    canvas.parentElement.appendChild(this.labelRenderer.domElement);

    this.topologyLayer = null;
    this._raycaster = new THREE.Raycaster();
    this._pointer = new THREE.Vector2();
  }

  /** Adjunta (o reemplaza) la capa de topología 3D con datos del backend. */
  setTopology(topology) {
    if (this.topologyLayer) {
      this.scene.remove(this.topologyLayer.group);
    }
    this.topologyLayer = buildTopology(topology);
    this.scene.add(this.topologyLayer.group);
  }

  /** Sincroniza el conjunto de nodos aislados con la capa de topología. */
  setIsolated(nodeIds) {
    if (this.topologyLayer) this.topologyLayer.setIsolated(nodeIds);
  }

  /** Lanza una partícula que recorre la ruta lógica del flujo. */
  spawnFlow(flow) {
    if (this.topologyLayer) this.topologyLayer.spawnFlow(flow);
  }

  /** Raycasting: dado un (clientX, clientY) devuelve el nodo de topología
   *  bajo el cursor o `null` si el rayo no impacta ningún nodo. */
  pickNode(clientX, clientY) {
    if (!this.topologyLayer) return null;
    const rect = this.canvas.getBoundingClientRect();
    this._pointer.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    this._pointer.y = -((clientY - rect.top) / rect.height) * 2 + 1;
    this._raycaster.setFromCamera(this._pointer, this.camera);

    const meshes = Array.from(this.topologyLayer.nodeMeshes.values());
    const hits = this._raycaster.intersectObjects(meshes, false);
    return hits.length ? hits[0].object.userData.node : null;
  }

  resize(w, h) {
    this.renderer.setSize(w, h, false);
    this.labelRenderer.setSize(w, h);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
  }

  update(state, dt, t) {
    this.uniforms.uTime.value = t;
    this.uniforms.uH.value = state.smoothedH;
    this.uniforms.uPulse.value = state.pulse;
    this.uniforms.uBlockPulse.value = state.blockPulse;
    this.uniforms.uAttackOrigin.value.set(
      state.attackOrigin.x,
      state.attackOrigin.y,
      state.attackOrigin.z,
    );
    this.wire.rotation.y -= dt * 0.1;
    if (this.topologyLayer) this.topologyLayer.update(state, dt, t);
    this.controls.update();
  }

  render() {
    this.renderer.render(this.scene, this.camera);
    this.labelRenderer.render(this.scene, this.camera);
  }
}
