import crypto from "node:crypto";
import { json, strictJson, normalizeIdentifier, clientIp, getSecurityStore, issueSessionHeaders, writeSession, maybeSendToSiem, serviceTokenVerify } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

function emailKey(email) {
  return "user:" + crypto.createHash("sha256").update(email).digest("hex");
}

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const name = normalizeIdentifier(body.name, 80);
  const email = normalizeIdentifier(body.email, 120).toLowerCase();
  const password = typeof body.password === "string" ? body.password.slice(0, 200) : "";
  const termsAccepted = body.termsAccepted === true;
  const mouseToken = typeof body.mouseToken === "string" ? body.mouseToken : "";
  const verifiedMouse = serviceTokenVerify(mouseToken);

  if (!name || !email || !password || password.length < 8) return json({ ok: false, error: "invalid-input" }, 400);
  if (!termsAccepted) return json({ ok: false, error: "terms-required" }, 400);
  if (!verifiedMouse || verifiedMouse.type !== "mouse_signup") return json({ ok: false, error: "mouse-challenge-required" }, 400);

  const findings = inspectStrings([name, email]);
  if (findings.length) return json({ ok: false, error: "malicious-input" }, 403);

  const store = await getSecurityStore();
  const key = emailKey(email);
  const existing = await store.getJSON(key);
  if (existing) return json({ ok: false, error: "already-exists" }, 409);

  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = crypto.scryptSync(password, salt, 64).toString("hex");
  const userId = crypto.randomUUID();

  const record = { id: userId, name, email, salt, passwordHash, createdAt: new Date().toISOString() };
  await store.setJSON(key, record);

  const sessionId = crypto.randomBytes(24).toString("base64url");
  const csrfToken = crypto.randomBytes(24).toString("base64url");
  await writeSession(sessionId, {
    username: email,
    displayName: name,
    role: "user",
    userId,
    csrf: csrfToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  });

  await maybeSendToSiem({ type: "user_signup", userId, email, ip: clientIp(req), ts: Date.now() });
  return json({ ok: true, csrfToken }, 201, { "Set-Cookie": issueSessionHeaders(sessionId) });
};
