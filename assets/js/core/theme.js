// theme.js — project override of theme partial (shadows themes/hextra/assets/js/core/theme.js
// inside the main.js bundle via resources.Match "js/core/*.js").
//
// Replaces the 3-option dropdown behavior with a single-click light<->dark toggle.
// System remains the default on first visit (per [params.theme] default = "system");
// the first click pins an explicit theme and the button becomes a pure toggle thereafter.
//
// setTheme() is a global defined by js/head/theme.js (loaded in <head>), which sets the
// .light/.dark class on <html> and updates colorScheme to avoid a flash on load.

(function () {
  const defaultTheme = '{{ site.Params.theme.default | default `system`}}';
  const themes = ["light", "dark"];

  const themeToggleButtons = document.querySelectorAll(".hextra-theme-toggle");

  // Resolve an explicit "light" or "dark" from a possibly-"system" value,
  // using the OS preference. Used to pick which icon to show and which theme to flip to.
  function resolveTheme(theme) {
    if (themes.includes(theme)) return theme;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  // Update every toggle button's wrapper data-theme so the correct icon shows.
  // data-theme drives the group-data-[theme=...] visibility classes in the partial.
  function syncButtonLabels(theme) {
    const effective = resolveTheme(theme);
    themeToggleButtons.forEach((btn) => {
      btn.parentElement.dataset.theme = effective;
    });
  }

  function applyTheme(theme) {
    // Persist the user's choice. "system" is only ever the initial default; after the
    // first click we always store an explicit theme, so this stays light/dark from then on.
    localStorage.setItem("color-theme", theme);
    setTheme(theme);
    syncButtonLabels(theme);
  }

  function switchTheme(theme) {
    applyTheme(theme);
  }

  // Initialize from localStorage or the configured default.
  const colorTheme = "color-theme" in localStorage ? localStorage.getItem("color-theme") : defaultTheme;
  switchTheme(colorTheme);

  // Single-click toggle: flip to the explicit opposite of the current effective theme.
  themeToggleButtons.forEach((toggler) => {
    toggler.addEventListener("click", function (e) {
      e.preventDefault();
      const current = resolveTheme(localStorage.getItem("color-theme") || defaultTheme);
      const next = current === "dark" ? "light" : "dark";
      switchTheme(next);
    });
  });

  // If the user has not clicked yet (still in "system" mode), follow OS theme changes
  // so the page + icon stay in sync with the OS preference.
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (localStorage.getItem("color-theme") === "system") {
      setTheme("system");
      syncButtonLabels("system");
    }
  });
})();