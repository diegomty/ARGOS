// Dashboard lateral: 3 paneles que reflejan en vivo el flujo de eventos.
//   Panel 1 — Cadena SHA-3-256: integridad post-cuántica de cada log.
//   Panel 2 — Amenazas neutralizadas: histórico de IPs bloqueadas.
//   Panel 3 — Consola SSH: cada comando ejecutado contra el router.

import { state } from './state.js';

const HASH_HISTORY = 14;
const SSH_HISTORY = 80;

const $hashStream = document.getElementById('hash-stream');
const $hashCounter = document.getElementById('hash-counter');
const $blockedList = document.getElementById('blocked-list');
const $blockedCounter = document.getElementById('blocked-counter');
const $sshConsole = document.getElementById('ssh-console');
const $sshCounter = document.getElementById('ssh-counter');

const blockedHistory = new Map(); // ip → { firstSeen, lastSeen, attempts, plan }
let sshLineCount = 0;

export function pushDashboard(ev) {
  renderHash(ev);
  renderBlocked(ev);
  renderSsh(ev);
}

// --- Panel 1: SHA-3 stream ---

function renderHash(ev) {
  const row = document.createElement('div');
  const cls = ev.is_anomaly ? 'anom' : (ev.is_trusted ? 'trust' : 'norm');
  row.className = 'hash-row ' + cls;
  const ts = ev.timestamp.split(' ')[1].slice(0, 12);
  const hashShort = ev.sha3.slice(0, 24);
  const raw = escapeHtml(ev.raw_message || '');
  row.innerHTML = `
    <div class="hash-row-head">
      <span class="ts">${ts}</span>
      <span class="hash">${hashShort}…</span>
    </div>
    <div class="hash-row-detail">
      <div class="hash-full"><span class="lbl">SHA-3</span>${ev.sha3}</div>
      <div class="raw-msg"><span class="lbl">MSG</span>${raw}</div>
    </div>
  `;
  row.addEventListener('click', () => row.classList.toggle('expanded'));
  $hashStream.prepend(row);
  while ($hashStream.children.length > HASH_HISTORY) {
    $hashStream.removeChild($hashStream.lastChild);
  }
  $hashCounter.textContent = state.totalEvents.toString();
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// --- Panel 2: amenazas neutralizadas ---

function renderBlocked(ev) {
  if (!ev.blocked || !ev.attacker_ip) return;

  const ip = ev.attacker_ip;
  const existing = blockedHistory.get(ip);
  if (existing) {
    existing.attempts++;
    existing.lastSeen = ev.timestamp;
  } else {
    blockedHistory.set(ip, {
      firstSeen: ev.timestamp,
      lastSeen: ev.timestamp,
      attempts: 1,
      plan: ev.plan,
    });
  }

  // Limpia el placeholder "sin amenazas detectadas" la primera vez.
  const empty = $blockedList.querySelector('.blocked-empty');
  if (empty) empty.remove();

  // Re-render completo (lista corta, no vale la pena diff).
  $blockedList.innerHTML = '';
  // Iteramos en reversa para mostrar primero los más recientes.
  const entries = [...blockedHistory.entries()].reverse();
  for (const [ip, info] of entries) {
    const row = document.createElement('div');
    row.className = 'blocked-row';
    row.innerHTML = `
      <div class="ip">${ip}</div>
      <div class="meta">
        <span class="plan plan-${info.plan}">PLAN ${info.plan}</span>
        <span class="attempts">${info.attempts} intento${info.attempts > 1 ? 's' : ''}</span>
      </div>
      <div class="time">primera: ${info.firstSeen.split(' ')[1].slice(0, 8)} · última: ${info.lastSeen.split(' ')[1].slice(0, 8)}</div>
    `;
    $blockedList.appendChild(row);
  }

  $blockedCounter.textContent = blockedHistory.size.toString();
}

// --- Panel 3: consola SSH (response_log) ---

function classifySshLine(line) {
  if (line.startsWith('  router#')) return 'cmd';
  if (line.startsWith('[!]')) return 'warn';
  if (line.startsWith('[✓]')) return 'ok';
  if (line.startsWith('[X]')) return 'err';
  return '';
}

function renderSsh(ev) {
  if (!ev.response_log || !ev.response_log.length) return;

  const empty = $sshConsole.querySelector('.ssh-empty');
  if (empty) empty.remove();

  for (const line of ev.response_log) {
    const lineEl = document.createElement('div');
    lineEl.className = 'ssh-line ' + classifySshLine(line);
    lineEl.textContent = line;
    $sshConsole.appendChild(lineEl);
    sshLineCount++;
  }
  while ($sshConsole.children.length > SSH_HISTORY) {
    $sshConsole.removeChild($sshConsole.firstChild);
  }
  $sshConsole.scrollTop = $sshConsole.scrollHeight;
  $sshCounter.textContent = sshLineCount.toString();
}
