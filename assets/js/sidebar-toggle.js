document.addEventListener('DOMContentLoaded', function () {
  var btn = document.createElement('button');
  btn.id = 'sidebar-toggle';
  btn.title = 'Toggle Sidebar';
  btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="9" y1="3" x2="9" y2="21"/></svg>';

  btn.style.cssText = 'position:fixed;bottom:1.2rem;left:1.2rem;z-index:9999;background:transparent;border:1px solid #e63946;color:#e63946;border-radius:6px;padding:6px 8px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:background 0.2s,color 0.2s;';

  btn.addEventListener('mouseenter', function(){ btn.style.background='#e63946'; btn.style.color='#fff'; });
  btn.addEventListener('mouseleave', function(){ btn.style.background='transparent'; btn.style.color='#e63946'; });

  document.body.appendChild(btn);

  var sidebar = document.querySelector('aside') ||
                document.querySelector('[class*="sidebar"]');

  var collapsed = false;

  btn.addEventListener('click', function () {
    collapsed = !collapsed;
    if (sidebar) {
      sidebar.style.transition = 'width 0.3s ease, min-width 0.3s ease';
      if (collapsed) {
        sidebar.dataset.width = sidebar.offsetWidth;
        sidebar.style.width = '0';
        sidebar.style.minWidth = '0';
        sidebar.style.overflow = 'hidden';
      } else {
        sidebar.style.width = '';
        sidebar.style.minWidth = '';
        sidebar.style.overflow = '';
      }
    }
  });
});