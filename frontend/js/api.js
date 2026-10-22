// Tiny fetch wrapper. The server is the only authority: this file never decides who may do what.
async function api(path, opts = {}) {
  const o = { credentials: "same-origin", ...opts, headers: { "X-Requested-With": "trustvault", ...(opts.headers || {}) } };
  if (opts.json) { o.body = JSON.stringify(opts.json); o.headers["Content-Type"] = "application/json"; o.method = o.method || "POST"; }
  const r = await fetch(path, o);
  if (r.status === 401 && location.pathname.includes("dashboard")) location.href = "/login.html";
  if (!r.ok) {
    let d = null; try { d = await r.json(); } catch (e) {}
    throw new Error(typeof (d && d.detail) === "string" ? d.detail : "Please check what you entered");
  }
  return opts.raw ? r : r.json();
}
