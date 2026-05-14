// Ticker compacto en la parte inferior — feed horizontal de eventos.

const MAX_VISIBLE = 40;
const container = document.getElementById('ticker');

export function pushTicker(ev) {
  const el = document.createElement('div');
  el.className = 'tick ' + (ev.is_anomaly ? 'anomaly' : 'benign');
  const tail = ev.attacker_ip
    ? `· <span style="color:var(--red)">${ev.attacker_ip}</span> (plan ${ev.plan})`
    : '';
  el.innerHTML = `
    <span class="ts">${ev.timestamp.split(' ')[1]}</span>
    H=<span class="h-val">${ev.entropy.toFixed(2)}</span>
    SHA3=<span style="color:var(--muted)">${ev.sha3.slice(0, 8)}…</span>
    ${tail}
  `;
  container.prepend(el);
  while (container.children.length > MAX_VISIBLE) {
    container.removeChild(container.lastChild);
  }
}
