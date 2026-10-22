/* Secure Cloud Storage - dashboard (vanilla JS, no build step).
 *
 * Security notes:
 *  - File names are user-controlled, so the DOM is built with textContent /
 *    createTextNode only (helper `h`). innerHTML is used solely for the static
 *    SVG icon strings below.
 *  - Every API call carries the CSRF token in the X-CSRF-Token header.
 */
(() => {
  "use strict";

  const root = document.getElementById("app");
  const CSRF = root.dataset.csrf;
  const $ = (id) => document.getElementById(id);

  const state = {
    view: "files", files: [], shares: [], activity: [],
    usage: { used: 0, quota: 1, count: 0 }, query: "", sort: "new",
  };

  /* ---------- tiny DOM helpers ---------- */
  const h = (tag, attrs, ...kids) => {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v == null) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat()) {
      if (kid == null || kid === false) continue;
      el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    }
    return el;
  };

  const ICONS = {
    files: '<path d="M4 5h6l2 2h8v12a1 1 0 0 1-1 1H4z"/>',
    link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    download: '<path d="M12 4v10"/><path d="M8 10l4 4 4-4"/><path d="M5 19h14"/>',
    share: '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 11l7.6-4M8.2 13l7.6 4"/>',
    edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/>',
    trash: '<path d="M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13"/>',
    upload: '<path d="M12 16V5"/><path d="M8 9l4-4 4 4"/><path d="M5 19h14"/>',
    copy: '<rect x="8" y="8" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
    x: '<path d="M6 6l12 12M18 6L6 18"/>',
    check: '<path d="M5 12l5 5 9-10"/>',
    alert: '<path d="M12 8v5M12 16.5v.01"/><circle cx="12" cy="12" r="9"/>',
    theme: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4"/>',
    key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
    out: '<path d="M10 4H5v16h5"/><path d="M15 8l4 4-4 4M19 12H9"/>',
    login: '<path d="M14 4h5v16h-5"/><path d="M9 8l-4 4 4 4M5 12h10"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 20c1-4 4-6 8-6s7 2 8 6"/>',
  };
  const icon = (name, size = 18) => {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    for (const [k, v] of Object.entries({ viewBox: "0 0 24 24", width: size, height: size, fill: "none",
      stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" }))
      s.setAttribute(k, v);
    s.innerHTML = ICONS[name];
    return s;
  };

  /* ---------- formatting ---------- */
  const fmtBytes = (n) => {
    const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0, v = n;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)) + " " + u[i];
  };
  const ago = (iso) => {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 45) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    if (s < 86400 * 30) return Math.round(s / 86400) + " d ago";
    return new Date(iso).toLocaleDateString();
  };
  const absTime = (iso) => new Date(iso).toLocaleString();
  const until = (iso) => {
    if (!iso) return "Never expires";
    const ms = new Date(iso).getTime() - Date.now();
    if (ms <= 0) return "Expired";
    const hrs = ms / 3.6e6;
    return "Expires in " + (hrs < 1 ? Math.ceil(ms / 6e4) + " min" : hrs < 48 ? Math.round(hrs) + " h" : Math.round(hrs / 24) + " d");
  };

  const KINDS = {
    img: "png jpg jpeg gif webp svg bmp heic tiff", doc: "pdf doc docx txt md rtf odt ppt pptx key",
    sheet: "xls xlsx csv ods tsv numbers", code: "py js ts html css json xml c cpp java go rs sh sql yml yaml ipynb",
    arch: "zip rar 7z tar gz bz2 dmg iso", media: "mp3 wav flac mp4 mov avi mkv webm m4a",
  };
  const kindOf = (name) => {
    const ext = (name.includes(".") ? name.split(".").pop() : "").toLowerCase();
    for (const [k, list] of Object.entries(KINDS)) if (list.split(" ").includes(ext)) return [k, ext];
    return ["", ext];
  };
  const badge = (name) => {
    const [kind, ext] = kindOf(name);
    return h("div", { class: "file-badge " + kind }, (ext || "file").slice(0, 4).toUpperCase());
  };

  /* ---------- API ---------- */
  async function api(path, { method = "GET", json } = {}) {
    const headers = { "X-CSRF-Token": CSRF };
    let body;
    if (json !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(json); }
    const res = await fetch(path, { method, headers, body, credentials: "same-origin" });
    if (res.status === 401) { location.href = "/login"; throw new Error("Signed out"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  /* ---------- toasts & modal ---------- */
  function toast(message, kind = "ok") {
    const t = h("div", { class: "toast " + kind, role: "status" }, icon(kind === "ok" ? "check" : "alert"), message);
    $("toasts").append(t);
    setTimeout(() => t.remove(), kind === "ok" ? 3000 : 6000);
  }

  function modal({ title, body, footer }) {
    const prevFocus = document.activeElement;
    const close = () => { backdrop.remove(); document.removeEventListener("keydown", onKey); prevFocus && prevFocus.focus && prevFocus.focus(); };
    const onKey = (e) => { if (e.key === "Escape") close(); };
    const bodyEl = h("div", { class: "modal-body" }, body);
    const footEl = h("div", { class: "modal-foot" }, footer);
    const dialog = h("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-label": title },
      h("div", { class: "modal-head" }, h("h3", null, title),
        h("button", { class: "icon-btn", type: "button", "aria-label": "Close", onclick: close }, icon("x"))),
      bodyEl, footEl);
    const backdrop = h("div", { class: "modal-backdrop", onmousedown: (e) => { if (e.target === backdrop) close(); } }, dialog);
    $("modalRoot").append(backdrop);
    document.addEventListener("keydown", onKey);
    const first = dialog.querySelector("input, select, button.primary, button.danger");
    first && first.focus();
    return { close, bodyEl, footEl };
  }
  const cancelBtn = (m) => h("button", { class: "btn ghost", type: "button", onclick: () => m().close() }, "Cancel");

  /* ---------- data loading ---------- */
  async function refreshFiles() {
    const d = await api("/api/files");
    state.files = d.files; state.usage = d.usage;
  }
  async function loadView() {
    try {
      if (state.view === "files") await refreshFiles();
      else if (state.view === "shares") { const [s] = await Promise.all([api("/api/shares"), refreshFiles()]); state.shares = s.shares; }
      else { const [a] = await Promise.all([api("/api/activity"), refreshFiles()]); state.activity = a.items; }
    } catch (e) { if (e.message !== "Signed out") toast(e.message, "err"); }
    render();
  }
  function setView(v) {
    state.view = v; state.query = ""; $("search").value = "";
    loadView();
  }

  /* ---------- rendering ---------- */
  const TITLES = { files: "My files", shares: "Shared links", activity: "Activity" };

  function renderChrome() {
    const nav = $("nav");
    nav.replaceChildren(...[["files", "My files", state.usage.count], ["shares", "Shared links", null], ["activity", "Activity", null]]
      .map(([id, label, count]) => h("button", { class: "nav-item", type: "button", "aria-current": state.view === id ? "page" : false, onclick: () => setView(id) },
        icon(id === "shares" ? "link" : id), h("span", { class: "label" }, label), count ? h("span", { class: "count" }, count) : null)));
    $("viewTitle").textContent = TITLES[state.view];
    $("fileTools").hidden = state.view !== "files";

    const { used, quota } = state.usage;
    const pct = Math.min(100, (used / quota) * 100);
    $("meterFill").style.width = pct + "%";
    $("meterFill").parentElement.className = "meter" + (pct > 95 ? " danger" : pct > 80 ? " warn" : "");
    $("usageText").textContent = `${fmtBytes(used)} of ${fmtBytes(quota)} used`;
  }

  function render() {
    renderChrome();
    const c = $("content");
    if (state.view === "files") c.replaceChildren(renderFiles());
    else if (state.view === "shares") c.replaceChildren(renderShares());
    else c.replaceChildren(renderActivity());
  }

  function visibleFiles() {
    const q = state.query.trim().toLowerCase();
    const list = state.files.filter((f) => !q || f.name.toLowerCase().includes(q));
    const by = {
      new: (a, b) => b.created.localeCompare(a.created), old: (a, b) => a.created.localeCompare(b.created),
      name: (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }), size: (a, b) => b.size - a.size,
    }[state.sort];
    return list.sort(by);
  }

  function emptyState(title, text, withUpload) {
    return h("div", { class: "empty" }, icon("upload", 40), h("h2", null, title), h("p", null, text),
      withUpload ? h("button", { class: "btn primary", type: "button", onclick: () => $("fileInput").click() }, icon("upload", 16), "Choose files") : null);
  }

  function renderFiles() {
    if (!state.files.length) return emptyState("Your vault is empty", "Drag files anywhere on this page, or choose them. Each one gets its own random AES-256 key.", true);
    const files = visibleFiles();
    if (!files.length) return emptyState("No matches", `Nothing named “${state.query}”.`, false);
    const iconBtn = (name, label, props) => h(props.href ? "a" : "button", { class: "icon-btn" + (props.danger ? " danger" : ""), title: label, "aria-label": label, type: props.href ? false : "button", ...props }, icon(name));
    return h("div", { class: "list" },
      h("div", { class: "list-head" }, h("span", null, "Name"), h("span", null, "Size"), h("span", null, "Uploaded"), h("span")),
      files.map((f) => h("div", { class: "row" },
        h("div", { class: "cell-name" }, badge(f.name), h("span", { class: "fname", title: f.name }, f.name),
          f.shared ? h("span", { class: "pill", title: `${f.shared} active share link(s)` }, icon("link", 12), f.shared) : null),
        h("div", { class: "cell-size" }, fmtBytes(f.size)),
        h("div", { class: "cell-date", title: absTime(f.created) }, ago(f.created)),
        h("div", { class: "cell-actions" },
          iconBtn("download", "Download", { href: `/download/${f.id}` }),
          iconBtn("share", "Share", { onclick: () => openShare(f) }),
          iconBtn("edit", "Rename", { onclick: () => openRename(f) }),
          iconBtn("trash", "Delete", { danger: true, onclick: () => openDelete(f) })))));
  }

  function renderShares() {
    if (!state.shares.length) return emptyState("No share links yet", "Use the share icon on any file to create an expiring, download-limited link.", false);
    return h("div", { class: "list" }, state.shares.map((s) => h("div", { class: "row share-row" },
      h("div", { class: "cell-name" }, badge(s.name),
        h("div", { class: "cell-text" }, h("div", { class: "fname", title: s.name }, s.name),
          h("div", { class: "muted" }, `${until(s.expires_at)} · ${s.downloads}${s.max_downloads != null ? " / " + s.max_downloads : ""} downloads`))),
      h("div", null, h("span", { class: "status " + s.status }, s.status)),
      h("div", { class: "cell-date", title: absTime(s.created) }, "Created " + ago(s.created)),
      h("div", { class: "cell-actions" },
        h("button", { class: "icon-btn danger", type: "button", title: "Revoke link", "aria-label": "Revoke link", onclick: () => revokeShare(s) }, icon("trash"))))));
  }

  const EVENTS = {
    register: ["Account created", "user", "good"], login: ["Signed in", "login", "good"], login_failed: ["Failed sign-in attempt", "alert", "bad"],
    logout: ["Signed out", "out", ""], upload: ["Uploaded", "upload", ""], download: ["Downloaded", "download", ""],
    delete: ["Deleted", "trash", ""], rename: ["Renamed", "edit", ""], share_create: ["Created share link for", "link", ""],
    share_revoke: ["Revoked share link for", "link", ""], share_download: ["Someone downloaded via share link", "share", "good"],
    password_change: ["Changed password", "key", "good"],
  };
  function renderActivity() {
    if (!state.activity.length) return emptyState("No activity yet", "Sign-ins, uploads and share events will show up here.", false);
    return h("ul", { class: "timeline" }, state.activity.map((a) => {
      const [label, ic, tone] = EVENTS[a.event] || [a.event, "activity", ""];
      return h("li", null,
        h("span", { class: "tl-icon " + tone }, icon(ic, 16)),
        h("div", { class: "tl-text" }, h("div", { class: "what" }, label, a.name ? ` “${a.name}”` : ""), h("div", { class: "sub" }, a.ip ? "from " + a.ip : "")),
        h("span", { class: "tl-time", title: absTime(a.at) }, ago(a.at)));
    }));
  }

  /* ---------- actions ---------- */
  function openDelete(f) {
    let m;
    const btn = h("button", { class: "btn danger", type: "button", onclick: async () => {
      btn.disabled = true;
      try { await api(`/api/files/${f.id}`, { method: "DELETE" }); m.close(); toast("File deleted"); await loadView(); }
      catch (e) { btn.disabled = false; toast(e.message, "err"); }
    } }, "Delete permanently");
    m = modal({ title: "Delete file?", body: h("p", null, `“${f.name}” and all of its share links will be permanently removed. This can't be undone.`), footer: [cancelBtn(() => m), btn] });
  }

  function openRename(f) {
    let m;
    const input = h("input", { type: "text", value: f.name, maxlength: "255", "aria-label": "File name" });
    const go = async () => {
      const name = input.value.trim(); if (!name || name === f.name) return m.close();
      try { await api(`/api/files/${f.id}`, { method: "PATCH", json: { name } }); m.close(); toast("Renamed"); await loadView(); }
      catch (e) { toast(e.message, "err"); }
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    m = modal({ title: "Rename file", body: input, footer: [cancelBtn(() => m), h("button", { class: "btn primary", type: "button", onclick: go }, "Save")] });
    input.select();
  }

  function field(label, control) { return h("label", { class: "field" }, label, control); }
  function select(opts) { return h("select", null, opts.map(([v, t]) => h("option", { value: v }, t))); }

  function openShare(f) {
    let m;
    const hours = select([["1", "1 hour"], ["24", "24 hours"], ["168", "7 days"], ["720", "30 days"], ["", "Never"]]); hours.value = "24";
    const max = select([["", "Unlimited"], ["1", "1 download"], ["5", "5 downloads"], ["10", "10 downloads"], ["25", "25 downloads"]]);
    const create = h("button", { class: "btn primary", type: "button" }, icon("link", 16), "Create link");
    m = modal({
      title: `Share “${f.name}”`,
      body: [h("p", { class: "muted" }, "Anyone with the link can download this file until it expires or hits its limit. The decryption key is embedded in the link (after the #) and is never stored on the server."),
        h("div", { class: "two-col" }, field("Expires after", hours), field("Download limit", max))],
      footer: [cancelBtn(() => m), create],
    });
    create.addEventListener("click", async () => {
      create.disabled = true;
      try {
        const r = await api(`/api/files/${f.id}/share`, { method: "POST", json: { hours: hours.value || null, max_downloads: max.value || null } });
        const link = `${location.origin}/s/${r.token}#${r.key}`;
        const input = h("input", { type: "text", readonly: true, value: link, "aria-label": "Share link" });
        const copy = h("button", { class: "btn primary", type: "button" }, icon("copy", 16), "Copy");
        copy.addEventListener("click", async () => {
          try { await navigator.clipboard.writeText(link); } catch { input.select(); document.execCommand("copy"); }
          toast("Link copied");
        });
        m.bodyEl.replaceChildren(h("p", null, "Link created. ", h("strong", null, "Copy it now"), " — the key isn't stored, so it can't be shown again."),
          h("div", { class: "copy-row" }, input, copy), h("p", { class: "muted" }, `${until(r.expires_at)} · ${r.max_downloads ? r.max_downloads + " download limit" : "unlimited downloads"}`));
        m.footEl.replaceChildren(h("button", { class: "btn primary", type: "button", onclick: () => m.close() }, "Done"));
        input.select();
        refreshFiles().then(render);
      } catch (e) { create.disabled = false; toast(e.message, "err"); }
    });
  }

  async function revokeShare(s) {
    try { await api(`/api/shares/${s.token}`, { method: "DELETE" }); toast("Link revoked"); await loadView(); }
    catch (e) { toast(e.message, "err"); }
  }

  /* ---------- uploads (queue + progress) ---------- */
  const queue = []; let running = false;

  function uploadOne(file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/upload");
      xhr.setRequestHeader("X-CSRF-Token", CSRF);
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
      xhr.onload = () => {
        let d = {}; try { d = JSON.parse(xhr.responseText); } catch { /* non-JSON error page */ }
        if (xhr.status === 401) { location.href = "/login"; return; }
        xhr.status < 300 ? resolve(d) : reject(new Error(d.error || `Upload failed (${xhr.status})`));
      };
      xhr.onerror = () => reject(new Error("Network error"));
      const fd = new FormData(); fd.append("file", file);
      xhr.send(fd);
    });
  }

  function uploadItem(file) {
    const fill = h("span"), status = h("span", { class: "s" }, "Waiting");
    const meter = h("div", { class: "meter" }, fill);
    const el = h("div", { class: "up-item" }, h("div", { class: "up-top" }, h("span", { class: "n", title: file.name }, file.name), status), meter);
    const panel = $("uploads");
    if (!panel.children.length) panel.append(h("div", { class: "uploads-head" }, "Uploads"));
    panel.hidden = false; panel.append(el);
    return {
      progress(p) { fill.style.width = (p * 100) + "%"; status.textContent = p >= 1 ? "Encrypting…" : Math.round(p * 100) + "%"; },
      done() { el.className = "up-item done"; fill.style.width = "100%"; status.textContent = "Encrypted ✓"; },
      fail(msg) { el.className = "up-item fail"; status.textContent = msg; },
    };
  }

  async function runQueue() {
    running = true;
    let ok = 0;
    while (queue.length) {
      const { file, item } = queue.shift();
      try { await uploadOne(file, item.progress); item.done(); ok++; }
      catch (e) { item.fail(e.message); toast(`${file.name}: ${e.message}`, "err"); }
      if (state.view === "files") await refreshFiles().then(render).catch(() => {}); else await refreshFiles().then(renderChrome).catch(() => {});
    }
    running = false;
    if (ok) toast(`${ok} file${ok > 1 ? "s" : ""} encrypted & stored`);
    setTimeout(() => { if (!running) { $("uploads").replaceChildren(); $("uploads").hidden = true; } }, 5000);
  }

  function enqueue(fileList) {
    const files = [...fileList].filter((f) => f.size >= 0);
    if (!files.length) return;
    if (state.view !== "files") { state.view = "files"; render(); }
    for (const file of files) queue.push({ file, item: uploadItem(file) });
    if (!running) runQueue();
  }

  /* ---------- wiring ---------- */
  function init() {
    const user = root.dataset.username;
    $("uname").textContent = user; $("avatar").textContent = user.slice(0, 1).toUpperCase();
    $("themeBtn").append(icon("theme")); $("pwBtn").append(icon("key")); $("outBtn").append(icon("out"));
    $("uploadBtn").append(icon("upload", 16), "Upload");

    $("uploadBtn").addEventListener("click", () => $("fileInput").click());
    $("fileInput").addEventListener("change", (e) => { enqueue(e.target.files); e.target.value = ""; });
    $("search").addEventListener("input", (e) => { state.query = e.target.value; render(); });
    $("sort").addEventListener("change", (e) => { state.sort = e.target.value; render(); });

    // drag & drop anywhere on the page
    let depth = 0;
    const hasFiles = (e) => e.dataTransfer && [...e.dataTransfer.types].includes("Files");
    window.addEventListener("dragenter", (e) => { if (hasFiles(e)) { depth++; $("dropOverlay").hidden = false; } });
    window.addEventListener("dragleave", (e) => { if (hasFiles(e) && --depth <= 0) { depth = 0; $("dropOverlay").hidden = true; } });
    window.addEventListener("dragover", (e) => { if (hasFiles(e)) e.preventDefault(); });
    window.addEventListener("drop", (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth = 0; $("dropOverlay").hidden = true; enqueue(e.dataTransfer.files); });

    document.addEventListener("keydown", (e) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if (e.key === "/" && !typing && state.view === "files") { e.preventDefault(); $("search").focus(); }
    });

    // server-side flash messages (e.g. after a password change) become toasts
    document.querySelectorAll("#flashes span").forEach((s) =>
      toast(s.textContent, s.dataset.kind === "error" ? "err" : "ok"));

    render();
    loadView();
  }
  init();
})();
