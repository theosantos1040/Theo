let csrfToken = null;

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      ...(csrfToken ? { "x-csrf-token": csrfToken } : {}),
      ...(options.headers || {})
    },
    ...options
  });
  const data = await res.json().catch(() => ({ ok: false, error: "bad-response" }));
  return { res, data };
}

function setLoggedIn(on) {
  document.getElementById("loginBox").style.display = on ? "none" : "block";
  document.getElementById("sessionBox").style.display = on ? "block" : "none";
  document.getElementById("adminArea").style.display = on ? "block" : "none";
  document.getElementById("lockedArea").style.display = on ? "none" : "block";
}

function renderKeys(items) {
  const box = document.getElementById("keysList");
  box.innerHTML = "";
  if (!items.length) {
    box.innerHTML = "<p class=\"muted\">Nenhuma chave emitida ainda.</p>";
    return;
  }
  for (const item of items) {
    const div = document.createElement("div");
    div.className = "key-item";
    div.innerHTML = `
      <strong>${escapeHtml(item.label)}</strong>
      <div class="muted">Criada por ${escapeHtml(item.createdBy)} em ${escapeHtml(item.createdAt)}</div>
      <pre>Public ID:
${escapeHtml(item.publicId)}

Secret:
${escapeHtml(item.secret)}

Public Key:
${escapeHtml(item.publicKeyPem)}

Private Key:
${escapeHtml(item.privateKeyPem)}</pre>
    `;
    box.appendChild(div);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function refreshSession() {
  const { data } = await api("/api/admin/session", { method: "GET" });
  if (!data.ok) {
    csrfToken = null;
    setLoggedIn(false);
    return;
  }
  csrfToken = data.csrfToken;
  setLoggedIn(true);
  await refreshKeys();
}

async function refreshKeys() {
  const { data } = await api("/api/admin/keys", { method: "GET" });
  if (!data.ok) return;
  renderKeys(data.items || []);
}

document.getElementById("loginBtn").addEventListener("click", async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const { data } = await api("/api/admin/login", {
    method: "POST",
    body: JSON.stringify({ username, password })
  });
  const msg = document.getElementById("loginMsg");
  if (!data.ok) {
    msg.className = "error";
    msg.textContent = data.error === "locked" ? "Temporariamente bloqueado por tentativas." : "Falha no login.";
    return;
  }
  msg.className = "success";
  msg.textContent = "Login realizado.";
  csrfToken = data.csrfToken;
  await refreshSession();
});

document.getElementById("logoutBtn").addEventListener("click", async () => {
  await api("/api/admin/logout", { method: "POST", body: "{}" });
  await refreshSession();
});

document.getElementById("generateBtn").addEventListener("click", async () => {
  const label = document.getElementById("keyLabel").value || "ASO Key";
  const { data } = await api("/api/admin/keys", {
    method: "POST",
    body: JSON.stringify({ label })
  });
  const msg = document.getElementById("actionMsg");
  if (!data.ok) {
    msg.className = "error";
    msg.textContent = "Não foi possível gerar as chaves.";
    return;
  }
  msg.className = "success";
  msg.textContent = "Chaves geradas com sucesso.";
  document.getElementById("keyLabel").value = "";
  await refreshKeys();
});

refreshSession();
