// Public share page. The decryption key lives in the URL fragment (#...), which
// browsers never send to the server; we post it in the request body ourselves.
(() => {
  "use strict";
  const box = document.getElementById("share");
  const token = box.dataset.token;
  const key = location.hash.slice(1);

  const $ = (id) => document.getElementById(id);
  const status = $("status"), fname = $("fname"), fmeta = $("fmeta"), dl = $("dl"), badge = $("badge");

  const fmtBytes = (n) => {
    const u = ["B", "KB", "MB", "GB"]; let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
  };

  async function post(path) {
    const res = await fetch(path, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return res;
  }

  function fail(message) {
    status.textContent = message;
    status.style.color = "var(--danger)";
    badge.textContent = "!";
    dl.hidden = true;
  }

  async function init() {
    if (!key) return fail("This link is missing its key. Use the full URL, including the part after #.");
    try {
      const meta = await (await post(`/api/s/${encodeURIComponent(token)}/meta`)).json();
      const ext = (meta.name.split(".").pop() || "").slice(0, 4).toUpperCase();
      badge.textContent = ext && ext.length < meta.name.length ? ext : "FILE";
      status.textContent = "Someone shared a file with you";
      fname.textContent = meta.name; fname.hidden = false;
      const bits = [fmtBytes(meta.size)];
      if (meta.expires_at) bits.push("expires " + new Date(meta.expires_at).toLocaleString());
      if (meta.max_downloads != null) bits.push(`${meta.max_downloads - meta.downloads} download(s) left`);
      fmeta.textContent = bits.join(" · "); fmeta.hidden = false;
      dl.hidden = false;

      dl.addEventListener("click", async () => {
        dl.disabled = true; dl.textContent = "Decrypting…";
        try {
          const res = await post(`/api/s/${encodeURIComponent(token)}/file`);
          const url = URL.createObjectURL(await res.blob());
          const a = document.createElement("a");
          a.href = url; a.download = meta.name; document.body.append(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(url), 10000);
          dl.textContent = "Downloaded ✓";
        } catch (e) {
          fail(e.message);
        }
      });
    } catch (e) {
      fail(e.message);
    }
  }
  init();
})();
