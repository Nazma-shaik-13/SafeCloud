const form = document.getElementById("f"), msg = document.getElementById("msg");
form.addEventListener("submit", async (e) => {
  e.preventDefault(); msg.textContent = "";
  const d = Object.fromEntries(new FormData(form));
  try {
    if (document.body.dataset.mode === "signup") await api("/signup", { json: { email: d.email, password: d.password, role: d.role } });
    await api("/login", { json: { email: d.email, password: d.password } });
    location.href = "/dashboard.html";
  } catch (err) { msg.textContent = err.message; }
});
