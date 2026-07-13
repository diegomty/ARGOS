// Consola modular: barra vertical de módulos + conmutación de vistas.
//
// Cada vista es una <section class="view" data-view="ID"> y en la barra hay
// un botón .rail-item[data-view="ID"]. Al hacer clic se activa esa vista y se
// ocultan las demás. Las vistas pesadas (el gemelo 3D) siguen montadas aunque
// estén ocultas; al volver a mostrarlas re-disparamos un resize para que se
// reajusten al contenedor, que pudo cambiar de tamaño mientras estaba oculto.
//
// Los módulos que necesiten (re)dibujar al mostrarse escuchan el evento
// `viewchange` (detail.id). Así el mapa (L-2) sabe cuándo renderizar.

const items = document.querySelectorAll('.rail-item[data-view]');
const views = document.querySelectorAll('.view[data-view]');

function activate(id) {
  views.forEach(v => v.classList.toggle('active', v.dataset.view === id));
  items.forEach(i => i.classList.toggle('active', i.dataset.view === id));

  document.dispatchEvent(new CustomEvent('viewchange', { detail: { id } }));

  // El gemelo 3D se reajusta mediante el listener de resize ya existente
  // en main.js; forzamos un resize al volver a su vista.
  if (id === 'centinela') window.dispatchEvent(new Event('resize'));
}

for (const item of items) {
  if (item.disabled || item.classList.contains('is-soon')) continue;
  item.addEventListener('click', () => activate(item.dataset.view));
}
