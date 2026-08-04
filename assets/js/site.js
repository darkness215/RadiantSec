function initSidebarToggle() {
  var sidebar = document.querySelector('.hextra-sidebar-container');
  var toggleArea = document.querySelector('[data-toggle-animation="show"]');

  if (!toggleArea || document.getElementById('hextra-sidebar-toggle')) return;

  var btn = document.createElement('button');
  btn.id = 'hextra-sidebar-toggle';
  btn.title = 'Toggle Sidebar';

  function getIcon(collapsed) {
    return collapsed
      ? '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="15" y1="3" x2="15" y2="21"/></svg>'
      : '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/></svg>';
  }

  var collapsed = localStorage.getItem('hextra-sidebar-collapsed') === 'true';
  btn.innerHTML = getIcon(collapsed);

  function applyState() {
    if (sidebar) {
      sidebar.classList.toggle('hx-collapsed', collapsed);
    }
    btn.innerHTML = getIcon(collapsed);
    btn.title = collapsed ? 'Expand Sidebar' : 'Collapse Sidebar';
  }

  applyState();

  btn.addEventListener('click', function () {
    collapsed = !collapsed;
    localStorage.setItem('hextra-sidebar-collapsed', collapsed);
    applyState();
  });

  toggleArea.appendChild(btn);
}

document.addEventListener('DOMContentLoaded', initSidebarToggle);
window.addEventListener('load', initSidebarToggle);
setTimeout(initSidebarToggle, 300);

// Hero search button focuses the navbar search input.
// If the input isn't present (or search is collapsed on mobile), the anchor's
// own href is left intact as the fallback.
document.addEventListener('DOMContentLoaded', function () {
  var btn = document.getElementById('hero-search-btn');
  if (!btn) return;

  // Resolved on click, not at load, so resizing across the breakpoint can't
  // leave a dead button.
  btn.addEventListener('click', function (e) {
    var input = document.querySelector('.hextra-search-input');
    if (!input || input.offsetParent === null) return;
    e.preventDefault();
    input.scrollIntoView({ block: 'center' });
    input.focus();
  });
});

// Reading progress bar.
// The handler reads scrollHeight/clientHeight, which forces layout, so it is
// coalesced into one rAF per frame instead of running on every scroll event.
// Passive listener so it never blocks scrolling.
document.addEventListener('DOMContentLoaded', function () {
  if (document.getElementById('reading-progress')) return;

  var bar = document.createElement('div');
  bar.id = 'reading-progress';
  document.body.prepend(bar);

  var ticking = false;
  function update() {
    var doc = document.documentElement;
    var max = doc.scrollHeight - doc.clientHeight;
    bar.style.width = (max > 0 ? (doc.scrollTop / max * 100) : 0) + '%';
    ticking = false;
  }

  window.addEventListener('scroll', function () {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(update);
  }, { passive: true });
});

// HTB machine index: difficulty/OS filtering and sorting via native <select>.
// Progressive enhancement — the grid renders complete and visible without JS;
// this only wires up the selects if they exist on the page.
document.addEventListener('DOMContentLoaded', function () {
  var filters = document.querySelector('[data-htb-filters]');
  var grid = document.querySelector('[data-htb-grid]');
  if (!filters || !grid) return;

  var cards = Array.prototype.slice.call(grid.querySelectorAll('.htb-machine'));
  var countEl = document.querySelector('[data-htb-count]');
  var emptyEl = document.querySelector('[data-htb-empty]');
  var active = { difficulty: 'all', os: 'all' };

  function apply() {
    var shown = 0;
    cards.forEach(function (card) {
      var okDiff = active.difficulty === 'all' || card.dataset.difficulty === active.difficulty;
      var okOs = active.os === 'all' || card.dataset.os === active.os;
      var visible = okDiff && okOs;
      card.hidden = !visible;
      if (visible) shown++;
    });
    if (countEl) countEl.textContent = shown + ' machine' + (shown === 1 ? '' : 's');
    if (emptyEl) emptyEl.hidden = shown !== 0;
  }

  filters.querySelectorAll('select[data-filter-group]').forEach(function (select) {
    var name = select.dataset.filterGroup;
    select.addEventListener('change', function () {
      active[name] = select.value;
      apply();
    });
  });

  var sortSelect = filters.querySelector('[data-sort-select]');
  if (sortSelect) {
    sortSelect.addEventListener('change', function () {
      var mode = sortSelect.value;
      var ordered = cards.slice().sort(function (a, b) {
        if (mode === 'difficulty') {
          return (a.dataset.rank - b.dataset.rank) ||
                 b.dataset.date.localeCompare(a.dataset.date);
        }
        return b.dataset.date.localeCompare(a.dataset.date);
      });
      ordered.forEach(function (c) { grid.appendChild(c); });
    });
  }
});
