import crypto from "node:crypto";
import { json, strictJson, normalizeIdentifier, getSecurityStore, issueSessionHeaders, writeSession } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

function emailKey(email) {
  return "user:" + crypto.createHash("sha256").update(email).digest("hex");
}

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const email = normalizeIdentifier(body.email, 120).toLowerCase();
  const password = typeof body.password === "string" ? body.password.slice(0, 200) : "";
  if (!email || !password) return json({ ok: false, error: "invalid-input" }, 400);

  const findings = inspectStrings([email]);
  if (findings.length) return json({ ok: false, error: "malicious-input" }, 403);

  const store = await getSecurityStore();
  const user = await store.getJSON(emailKey(email));
  if (!user) return json({ ok: false, error: "invalid-credentials" }, 401);

  const calculated = crypto.scryptSync(password, user.salt, 64).toString("hex");
  const a = Buffer.from(calculated, "hex");
  const b = Buffer.from(user.passwordHash, "hex");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return json({ ok: false, error: "invalid-credentials" }, 401);
  }

  const sessionId = crypto.randomBytes(24).toString("base64url");
  const csrfToken = crypto.randomBytes(24).toString("base64url");
  await writeSession(sessionId, {
    username: user.email,
    displayName: user.name,
    role: "user",
    userId: user.id,
    csrf: csrfToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  });

  return json({ ok: true, csrfToken }, 200, { "Set-Cookie": issueSessionHeaders(sessionId) });
};
