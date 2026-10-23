// Everything shown comes from the server. Data is inserted as TEXT (never innerHTML), so names can't inject scripts.
const $ = (id) => document.getElementById(id);
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v);
  }
  e.append(...kids); return e;
};
let me = null, shareDoc = null, replDoc = null;

function toast(text, bad) {
  const t = $("toast"); t.textContent = text; t.className = bad ? "bad" : ""; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 3500);
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message, true); } };
const fmtSize = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.ceil(n / 1024) + " KB");
const fmtDate = (s) => new Date(s).toLocaleString();

async function init() {
  me = await api("/me");
  $("who").textContent = `${me.email} · ${me.role}`;
  $("upload").hidden = me.role !== "owner";
  $("t-admin").hidden = me.role !== "admin";
  await loadDocs();
}

async function loadDocs() {
  const p = new URLSearchParams();
  for (const [k, v] of new FormData($("sf"))) if (v) p.set(k, v);
  const docs = await api("/documents?" + p);
  $("empty").hidden = docs.length > 0;
  $("docs").replaceChildren(...docs.map(card));
}

function card(d) {
  const canEdit = d.my_access === "owner" || d.my_access === "edit";
  const canRead = d.my_access !== "admin";                // admins see metadata only
  const btns = [];
  if (canRead) btns.push(h("button", { class: "btn sm", onclick: guard(() => download(d)) }, "Download"));
  if (canEdit) {
    btns.push(h("button", { class: "btn ghost sm", onclick: guard(() => rename(d)) }, "Rename"));
    btns.push(h("button", { class: "btn ghost sm", onclick: () => { replDoc = d; $("repl").click(); } }, "Replace file"));
  }
  if (d.my_access === "owner") {
    btns.push(h("button", { class: "btn ghost sm", onclick: guard(() => openShare(d)) }, "Share"));
    btns.push(h("button", { class: "btn danger sm", onclick: guard(() => del(d)) }, "Delete"));
  }
  return h("div", { class: "card doc" }, h("span", { class: "badge" }, d.my_access), h("h3", {}, d.name),
    h("div", { class: "meta" }, h("span", {}, `${d.category} · ${fmtSize(d.size_bytes)}`), h("span", {}, `Owner: ${d.owner_email}`),
      h("span", {}, `Added ${fmtDate(d.created_at)}`),
      ...(d.sha256 ? [h("span", { title: d.sha256 }, `SHA-256: ${d.sha256.slice(0, 16)}…`)] : [])), h("div", { class: "row" }, ...btns));
}

async function download(d) {
  const r = await api(`/documents/${d.id}/download`, { raw: true });
  const url = URL.createObjectURL(await r.blob());
  const a = h("a", { href: url, download: d.name }); document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}
async function rename(d) {
  const name = prompt("New name (keep the extension)", d.name); if (!name) return;
  const category = prompt("Category", d.category); if (!category) return;
  await api(`/documents/${d.id}`, { method: "PATCH", json: { name, category } }); toast("Saved"); loadDocs();
}
async function del(d) {
  if (!confirm(`Delete "${d.name}"?`)) return;
  await api(`/documents/${d.id}`, { method: "DELETE" }); toast("Deleted"); loadDocs();
}

// ----- sharing dialog -----
async function openShare(d) {
  shareDoc = d; $("dname").textContent = d.name; $("gerr").textContent = ""; await loadGrants(); $("dlg").showModal();
}
async function loadGrants() {
  const gs = await api(`/documents/${shareDoc.id}/grants`);
  $("grants").replaceChildren(...(gs.length ? gs.map((g) => h("div", { class: "grant" },
    h("span", {}, `${g.email} `, h("span", { class: "badge" }, g.level)),
    h("button", { class: "btn danger sm", onclick: guard(async () => {
      await api(`/documents/${shareDoc.id}/grants/${g.user_id}`, { method: "DELETE" }); toast("Access revoked"); loadGrants();
    }) }, "Revoke"))) : [h("p", { class: "mute" }, "Nobody else has access yet.")]));
}

// ----- admin activity -----
async function loadAudit() {
  const p = new URLSearchParams();
  if ($("fa").value) p.set("action", $("fa").value);
  if ($("fo").value) p.set("outcome", $("fo").value);
  const rows = await api("/admin/audit?" + p);
  $("audit").replaceChildren(...rows.map((r) => h("tr", {},
    h("td", {}, String(r.id)), h("td", {}, fmtDate(r.at)), h("td", {}, r.actor_email || "unknown"), h("td", {}, r.action),
    h("td", {}, h("span", { class: "badge " + (r.outcome === "allowed" ? "ok" : "no") }, r.outcome)),
    h("td", {}, r.document_id ? r.document_id.slice(0, 8) : ""), h("td", { class: "detail" }, JSON.stringify(r.detail)),
    h("td", { title: r.hash }, r.hash.slice(0, 10)))));
}

function tab(which) {
  $("p-docs").hidden = which !== "docs"; $("p-admin").hidden = which !== "admin";
  $("t-docs").classList.toggle("on", which === "docs"); $("t-admin").classList.toggle("on", which === "admin");
  if (which === "admin") guard(loadAudit)();
}

$("t-docs").onclick = () => tab("docs");
$("t-admin").onclick = () => tab("admin");
$("refresh").onclick = guard(loadAudit);
$("verify").onclick = guard(async () => {
  const v = await api("/admin/audit/verify");
  $("vres").textContent = v.ok ? ` Chain intact (${v.checked} events)` : ` BROKEN at event ${v.broken_at}`;
});
$("sf").onsubmit = (e) => { e.preventDefault(); guard(loadDocs)(); };
$("upf").onsubmit = guard(async (e) => {
  e.preventDefault(); await api("/documents", { method: "POST", body: new FormData($("upf")) });
  $("upf").reset(); toast("Uploaded"); loadDocs();
});
$("repl").onchange = guard(async () => {
  const f = $("repl").files[0]; if (!f || !replDoc) return;
  const fd = new FormData(); fd.append("file", f);
  await api(`/documents/${replDoc.id}/content`, { method: "PUT", body: fd }); $("repl").value = ""; toast("File replaced"); loadDocs();
});
$("gf").onsubmit = async (e) => {
  e.preventDefault(); $("gerr").textContent = "";
  try { await api(`/documents/${shareDoc.id}/grants`, { json: Object.fromEntries(new FormData($("gf"))) }); $("gf").reset(); loadGrants(); }
  catch (err) { $("gerr").textContent = err.message; }
};
$("close").onclick = () => $("dlg").close();
$("logout").onclick = guard(async () => { await api("/logout", { method: "POST" }); location.href = "/"; });
init().catch(() => {});
