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

// Reading progress bar
document.addEventListener('DOMContentLoaded', function() {
  var bar = document.createElement('div');
  bar.id = 'reading-progress';
  document.body.prepend(bar);

  window.addEventListener('scroll', function() {
    var scrollTop = document.documentElement.scrollTop;
    var scrollHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    bar.style.width = (scrollHeight > 0 ? (scrollTop / scrollHeight * 100) : 0) + '%';
  });
});
