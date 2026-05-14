// Modal de aislamiento de segmento. Se abre con `showNodeModal(node, isolated)`
// y dispara la acción al backend (`/api/isolate` o `/api/unisolate`); el
// estado global se sincroniza después vía WebSocket, así que solo cierra
// el modal cuando recibe respuesta exitosa.

const $ = (id) => document.getElementById(id);

const root      = $('node-modal');
const fLabel    = $('modal-node-label');
const fSubnet   = $('modal-node-subnet');
const fIface    = $('modal-node-iface');
const fState    = $('modal-node-state');
const fError    = $('modal-error');
const btnAction = $('modal-action');
const btnClose  = $('modal-close');
const btnCancel = $('modal-cancel');
const backdrop  = $('modal-backdrop');

let currentNode = null;
let currentIsolated = false;

export function showNodeModal(node, isolated) {
  currentNode = node;
  currentIsolated = isolated;

  fLabel.textContent = node.label;
  const sub = node.subnet ?? '—';
  fSubnet.textContent = node.vlan ? `${sub}  ·  VLAN ${node.vlan}` : sub;
  fIface.textContent = node.interface ?? '—';
  fState.textContent = isolated ? 'AISLADO' : 'ACTIVO';
  fState.className = 'modal-val ' + (isolated ? 'state-isolated' : 'state-active');

  if (isolated) {
    btnAction.textContent = '▶ REACTIVAR';
    btnAction.className = 'btn-action btn-reactivate';
  } else {
    btnAction.textContent = '▶ AISLAR SEGMENTO';
    btnAction.className = 'btn-action btn-isolate';
  }

  fError.textContent = '';
  fError.style.display = 'none';
  btnAction.disabled = false;

  root.classList.remove('hidden');
}

export function hideNodeModal() {
  root.classList.add('hidden');
  currentNode = null;
}

backdrop.addEventListener('click', hideNodeModal);
btnClose.addEventListener('click', hideNodeModal);
btnCancel.addEventListener('click', hideNodeModal);

btnAction.addEventListener('click', async () => {
  if (!currentNode) return;
  const endpoint = currentIsolated ? '/api/unisolate' : '/api/isolate';
  const originalLabel = btnAction.textContent;

  btnAction.disabled = true;
  btnAction.textContent = '...';
  fError.style.display = 'none';

  try {
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node_id: currentNode.id }),
    });
    const data = await r.json();
    if (!r.ok || data.success === false) {
      fError.textContent = data.error || `error HTTP ${r.status}`;
      fError.style.display = 'block';
      btnAction.disabled = false;
      btnAction.textContent = originalLabel;
      return;
    }
  } catch (e) {
    fError.textContent = 'error de red: ' + e.message;
    fError.style.display = 'block';
    btnAction.disabled = false;
    btnAction.textContent = originalLabel;
    return;
  }
  // Éxito → el WS broadcasteará el nuevo estado y la UI se actualizará sola.
  hideNodeModal();
});

// Esc cierra
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !root.classList.contains('hidden')) hideNodeModal();
});
