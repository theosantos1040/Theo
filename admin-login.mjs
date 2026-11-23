import crypto from "node:crypto";
import { CONFIG, json, strictJson, normalizeIdentifier, verifyPassword, clientIp, checkThrottle, failLogin, successLogin, writeSession, issueSessionHeaders, getSecurityStore } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const ip = clientIp(req);
  const throttle = await checkThrottle(ip);
  if (!throttle.ok) return json({ ok: false, error: "locked", retryAfterMs: throttle.retryAfterMs }, 429);

  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const username = normalizeIdentifier(body.username, 80);
  const password = typeof body.password === "string" ? body.password.slice(0, 200) : "";
  const findings = inspectStrings([username, password]);

  if (findings.length) {
    await failLogin(ip);
    return json({ ok: false, error: "malicious-input" }, 403);
  }

  if (!username || !password) {
    await failLogin(ip);
    return json({ ok: false, error: "missing-fields" }, 400);
  }

  if (username !== CONFIG.adminUser || !verifyPassword(password)) {
    await failLogin(ip);
    return json({ ok: false, error: "invalid-credentials" }, 401);
  }

  await successLogin(ip);
  const sessionId = crypto.randomBytes(24).toString("base64url");
  const csrfToken = crypto.randomBytes(24).toString("base64url");
  await writeSession(sessionId, {
    username,
    role: "superadmin",
    csrf: csrfToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  });

  const store = await getSecurityStore();
  await store.setJSON(`audit:login:${sessionId}`, { ip, ts: Date.now(), username });

  return json({ ok: true, csrfToken }, 200, {
    "Set-Cookie": issueSessionHeaders(sessionId)
  });
};
