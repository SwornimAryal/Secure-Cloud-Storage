// Loaded in <head> (blocking) so the theme is applied before first paint.
(function () {
  var theme = "dark";
  try {
    theme = localStorage.getItem("scs-theme") ||
      (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  } catch (e) { /* storage blocked: fall back to dark */ }
  document.documentElement.dataset.theme = theme;

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-theme-toggle]");
    if (!btn) return;
    var next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("scs-theme", next); } catch (e) { /* ignore */ }
  });
})();
