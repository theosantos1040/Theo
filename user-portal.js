let csrfToken = null;
let mouseToken = null;
let mouseState = { moves: 0, distance: 0, start: 0, lastX: null, lastY: null, verified: false, challengeId: null };

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
  
  const entry = {
    time: new Date().toLocaleTimeString(),
    url,
    status: res.status,
    error: data.error || null,
    requestId: data.requestId || res.headers.get("x-aso-request-id") || null
  };
  const list = window.__asoUiLogs || (window.__asoUiLogs = []);
  list.unshift(entry);
  window.__asoUiLogs = list.slice(0, 20);
  renderUiLogs();
  return { res, data };

}

function qs(id) { return document.getElementById(id); }

function showAuthMode(mode) {
  qs("signupBox").style.display = mode === "signup" ? "block" : "none";
  qs("loginBox").style.display = mode === "login" ? "block" : "none";
}

function setLoggedIn(on) {
  qs("sessionBox").style.display = on ? "block" : "none";
  qs("portalArea").style.display = on ? "block" : "none";
  qs("lockedArea").style.display = on ? "none" : "block";
  qs("authTabs").style.display = on ? "none" : "flex";
  if (!on) showAuthMode("signup");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderKeys(items) {
  const box = qs("keysList");
  box.innerHTML = "";
  if (!items.length) {
    box.innerHTML = '<p class="muted">Nenhuma chave gerada ainda.</p>';
    return;
  }
  for (const item of items) {
    const div = document.createElement("div");
    div.className = "key-item";
    div.innerHTML = `
      <strong>${escapeHtml(item.label)}</strong>
      <div class="muted">Plano ${escapeHtml(item.plan || "BASIC")} · Criada em ${escapeHtml(item.createdAt)}</div>
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

async function refreshSession() {
  const { data } = await api("/api/user/session", { method: "GET" });
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
  const { data } = await api("/api/user/keys", { method: "GET" });
  if (data.ok) renderKeys(data.items || []);
}

async function bootMouseChallenge() {
  const { data } = await api("/api/challenge/mouse", { method: "GET" });
  if (!data.ok) return;
  mouseState = { moves: 0, distance: 0, start: 0, lastX: null, lastY: null, verified: false, challengeId: data.challengeId };
  mouseToken = null;

  const pad = qs("mousePad");
  pad.addEventListener("mousemove", async (event) => {
    if (mouseState.verified) return;
    if (!mouseState.start) mouseState.start = performance.now();
    const rect = pad.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    if (mouseState.lastX !== null) {
      const dx = x - mouseState.lastX;
      const dy = y - mouseState.lastY;
      mouseState.distance += Math.sqrt(dx * dx + dy * dy);
    }

    mouseState.lastX = x;
    mouseState.lastY = y;
    mouseState.moves += 1;
    const duration = performance.now() - mouseState.start;
    qs("mouseMsg").textContent = `Movimentos: ${mouseState.moves} · Distância: ${Math.round(mouseState.distance)} · Tempo: ${Math.round(duration)}ms`;

    if (mouseState.moves >= 12 && mouseState.distance >= 220 && duration >= 1200) {
      const { data: verify } = await api("/api/challenge/mouse/verify", {
        method: "POST",
        body: JSON.stringify({
          challengeId: mouseState.challengeId,
          stats: { moves: mouseState.moves, distance: mouseState.distance, duration }
        })
      });
      if (verify.ok) {
        mouseState.verified = true;
        mouseToken = verify.token;
        qs("mouseMsg").className = "success";
        qs("mouseMsg").textContent = "Desafio validado com sucesso.";
      }
    }
  }, { passive: true });
}

qs("tabSignup").addEventListener("click", () => showAuthMode("signup"));
qs("tabLogin").addEventListener("click", () => showAuthMode("login"));

qs("signupBtn").addEventListener("click", async () => {
  const body = {
    name: qs("signupName").value,
    email: qs("signupEmail").value,
    password: qs("signupPassword").value,
    termsAccepted: qs("termsAccepted").checked,
    mouseToken
  };
  const { data } = await api("/api/user/signup", { method: "POST", body: JSON.stringify(body) });
  const msg = qs("signupMsg");
  msg.className = data.ok ? "success" : "error";
  msg.textContent = data.ok ? "Conta criada e login realizado." : `Não foi possível criar a conta: ${data.error || "erro"}`;
  if (data.ok) {
    csrfToken = data.csrfToken;
    await refreshSession();
  }
});

qs("loginBtn").addEventListener("click", async () => {
  const body = { email: qs("loginEmail").value, password: qs("loginPassword").value };
  const { data } = await api("/api/user/login", { method: "POST", body: JSON.stringify(body) });
  const msg = qs("loginMsg");
  msg.className = data.ok ? "success" : "error";
  msg.textContent = data.ok ? "Login realizado." : `Falha no login: ${data.error || "erro"}`;
  if (data.ok) {
    csrfToken = data.csrfToken;
    await refreshSession();
  }
});

qs("logoutBtn").addEventListener("click", async () => {
  await api("/api/user/logout", { method: "POST", body: "{}" });
  await refreshSession();
});

qs("generateBtn").addEventListener("click", async () => {
  const { data } = await api("/api/user/keys", {
    method: "POST",
    body: JSON.stringify({ label: qs("keyLabel").value || "Minha key", plan: qs("keyPlan").value || "BASIC" })
  });
  const msg = qs("actionMsg");
  msg.className = data.ok ? "success" : "error";
  msg.textContent = data.ok ? "Chaves geradas com sucesso." : `Não foi possível gerar a keypair: ${data.error || "erro"}`;
  if (data.ok) {
    qs("keyLabel").value = "";
    await refreshKeys();
  }
});

bootMouseChallenge();
refreshSession();


function renderUiLogs() {
  const box = document.getElementById("uiLogs");
  if (!box) return;
  const items = window.__asoUiLogs || [];
  if (!items.length) {
    box.innerHTML = '<p class="muted">Sem erros recentes.</p>';
    return;
  }
  box.innerHTML = items.map((item) => `
    <div class="key-item">
      <strong>${escapeHtml(item.time)} · ${escapeHtml(item.url)}</strong>
      <div class="muted">status ${escapeHtml(item.status)} · req ${escapeHtml(item.requestId || "-")}</div>
      <div class="${item.error ? "error" : "muted"}">${escapeHtml(item.error || "ok")}</div>
    </div>
  `).join("");
}
