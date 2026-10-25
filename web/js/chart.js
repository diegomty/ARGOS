// Chart de entropía sobre el tiempo — SVG plano, cero dependencias.
//
// Hace polling a `/api/timeseries` cada 5s y renderiza:
//   * Área cyan tenue + línea cyan: avg_h por bucket de 60s
//   * Puntos rojos de tamaño proporcional al anomaly_count del bucket
//   * Línea punteada ámbar en H=5.0 (umbral de detección)

const SVG_NS = 'http://www.w3.org/2000/svg';
const PAD = { top: 10, right: 14, bottom: 16, left: 30 };
const POLL_MS = 5000;
const BUCKET_S = 60;
const SHOW_BUCKETS = 30;  // últimos 30 min

// Lee un color del tema actual (variables CSS) con respaldo, para que la
// gráfica se vea bien en claro y oscuro.
function cv(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

export class TimeseriesChart {
  constructor(container) {
    this.container = container;
    this.svg = el('svg', {
      width: '100%', height: '100%',
      preserveAspectRatio: 'none',
    });
    this.svg.style.display = 'block';
    container.appendChild(this.svg);
    this._timer = null;
    window.addEventListener('resize', () => this._lastPoints && this.render(this._lastPoints));
    document.addEventListener('argos:themechange', () => this._lastPoints && this.render(this._lastPoints));
  }

  start() {
    this.refresh();
    this._timer = setInterval(() => this.refresh(), POLL_MS);
  }

  stop() {
    if (this._timer) { clearInterval(this._timer); this._timer = null; }
  }

  /** Forzar refresh inmediato — útil tras una acción de aislamiento. */
  pulse() {
    this.refresh();
  }

  async refresh() {
    try {
      const since = (Date.now() / 1000) - SHOW_BUCKETS * BUCKET_S;
      const r = await fetch(`/api/timeseries?bucket=${BUCKET_S}&since=${since}`);
      if (!r.ok) return;
      const data = await r.json();
      this._lastPoints = data.points || [];
      this.render(this._lastPoints);
    } catch (e) {
      console.warn('[chart]', e);
    }
  }

  render(points) {
    const rect = this.container.getBoundingClientRect();
    const W = rect.width, H = rect.height;
    if (W < 50 || H < 50) return;

    while (this.svg.firstChild) this.svg.removeChild(this.svg.firstChild);

    if (points.length === 0) {
      this.svg.appendChild(el('text', {
        x: W / 2, y: H / 2,
        'text-anchor': 'middle', 'dominant-baseline': 'middle',
        fill: cv('--muted', '#6c7a99'), 'font-size': 11,
        'font-family': 'ui-monospace, monospace',
      }, '— sin datos en los últimos 30 minutos —'));
      return;
    }

    // Y range fijado a [0, 7] para que el umbral H=5.0 quede a misma altura siempre.
    const yMax = 7;
    const yMin = 0;

    // X range: usamos el rango temporal solicitado (no solo el observado),
    // así el chart "se desplaza" suavemente aunque haya buckets sin tráfico.
    const now = Date.now() / 1000;
    const xMin = now - SHOW_BUCKETS * BUCKET_S;
    const xMax = now;

    const innerW = W - PAD.left - PAD.right;
    const innerH = H - PAD.top - PAD.bottom;
    const xs = ts => PAD.left + ((ts - xMin) / (xMax - xMin)) * innerW;
    const ys = h  => PAD.top + (1 - (h - yMin) / (yMax - yMin)) * innerH;

    // --- Eje Y: ticks discretos en 0, 2.5, 5, 7 ---
    for (const yv of [0, 2.5, 5, 7]) {
      const y = ys(yv);
      this.svg.appendChild(el('line', {
        x1: PAD.left, x2: W - PAD.right, y1: y, y2: y,
        stroke: cv('--border', '#1f2a44'), 'stroke-width': 1, opacity: yv === 5 ? 0 : 0.6,
      }));
      this.svg.appendChild(el('text', {
        x: PAD.left - 4, y: y + 3, 'text-anchor': 'end',
        fill: cv('--muted', '#6c7a99'), 'font-size': 9,
        'font-family': 'ui-monospace, monospace',
      }, yv.toFixed(1)));
    }

    // --- Línea umbral H=5.0 (ámbar punteado) ---
    const thY = ys(5);
    this.svg.appendChild(el('line', {
      x1: PAD.left, x2: W - PAD.right, y1: thY, y2: thY,
      stroke: cv('--amber', '#f5c14b'), 'stroke-width': 1, 'stroke-dasharray': '3 4', opacity: 0.6,
    }));

    // --- Área + línea de avg_h ---
    if (points.length >= 1) {
      const pts = points.map(p => ({
        x: xs(p.ts + BUCKET_S / 2),
        y: ys(Math.min(p.avg_h, yMax)),
        max: ys(Math.min(p.max_h, yMax)),
        anomaly: p.anomaly_count,
        count: p.count,
      }));

      // Área (avg)
      let d = '';
      for (let i = 0; i < pts.length; i++) {
        d += (i === 0 ? 'M' : 'L') + pts[i].x + ',' + pts[i].y;
      }
      const baseline = ys(0);
      d += ` L${pts[pts.length-1].x},${baseline} L${pts[0].x},${baseline} Z`;
      this.svg.appendChild(el('path', {
        d, fill: cv('--cyan', '#5ee0d6') + '2e', stroke: 'none',
      }));

      // Línea (avg)
      let ld = '';
      for (let i = 0; i < pts.length; i++) {
        ld += (i === 0 ? 'M' : 'L') + pts[i].x + ',' + pts[i].y;
      }
      this.svg.appendChild(el('path', {
        d: ld, fill: 'none', stroke: cv('--cyan', '#5ee0d6'), 'stroke-width': 1.5,
      }));

      // Marcadores de max_h cuando supera el umbral (cresta)
      for (const p of pts) {
        if (p.anomaly > 0) {
          this.svg.appendChild(el('circle', {
            cx: p.x, cy: p.max,
            r: 3 + Math.min(p.anomaly, 8) * 0.5,
            fill: cv('--red', '#ff4d6d'), opacity: 0.9,
          }));
        }
      }
    }

    // --- Eje X: marcas de tiempo cada 5 buckets (~5 minutos) ---
    const tickInterval = 5 * BUCKET_S;
    const firstTick = Math.ceil(xMin / tickInterval) * tickInterval;
    for (let t = firstTick; t < xMax; t += tickInterval) {
      const x = xs(t);
      this.svg.appendChild(el('line', {
        x1: x, x2: x, y1: H - PAD.bottom - 2, y2: H - PAD.bottom + 2,
        stroke: cv('--muted', '#6c7a99'), 'stroke-width': 1, opacity: 0.5,
      }));
      const date = new Date(t * 1000);
      const hh = String(date.getHours()).padStart(2, '0');
      const mm = String(date.getMinutes()).padStart(2, '0');
      this.svg.appendChild(el('text', {
        x: x, y: H - 3, 'text-anchor': 'middle',
        fill: cv('--muted', '#6c7a99'), 'font-size': 9,
        'font-family': 'ui-monospace, monospace',
      }, `${hh}:${mm}`));
    }
  }
}

function el(tag, attrs = {}, text) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  if (text != null) e.textContent = text;
  return e;
}
