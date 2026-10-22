// Password strength meter + show/hide toggle for the register / change-password forms.
(() => {
  "use strict";

  function score(pw) {
    let s = 0;
    if (pw.length >= 10) s++;
    if (pw.length >= 14) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\d/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    if (/(.)\1{3,}/.test(pw) || /^(1234|password|qwerty)/i.test(pw)) s = Math.max(0, s - 2);
    return Math.min(4, Math.max(0, s - (pw.length < 10 ? 1 : 0)));
  }
  const LABELS = ["Too weak", "Weak", "Fair", "Good", "Strong"];

  document.querySelectorAll("[data-strength]").forEach((input) => {
    const meter = document.getElementById(input.dataset.strength);
    if (!meter) return;
    const fill = meter.querySelector("span");
    const text = meter.querySelector("small");
    input.addEventListener("input", () => {
      const v = input.value;
      const s = v ? score(v) : -1;
      meter.dataset.level = String(s);
      fill.style.width = s < 0 ? "0%" : `${(s + 1) * 20}%`;
      text.textContent = s < 0 ? "" : LABELS[s];
    });
  });

  document.querySelectorAll("[data-reveal]").forEach((btn) => {
    const targets = btn.dataset.reveal.split(",").map((id) => document.getElementById(id.trim()));
    btn.addEventListener("click", () => {
      const show = targets[0].type === "password";
      targets.forEach((t) => t && (t.type = show ? "text" : "password"));
      btn.textContent = show ? "Hide" : "Show";
    });
  });
})();
