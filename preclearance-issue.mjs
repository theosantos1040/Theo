import { json, strictJson, clientIp, sha256Hex, getSecurityStore, makePreclearanceToken } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const ip = clientIp(req);
  const fpKey = sha256Hex(JSON.stringify(body.fp || {}) + "|" + (body.ua || ""));
  const store = await getSecurityStore();
  const lastTelemetry = await store.getJSON(`telemetry:last:${fpKey}`);
  const score = Number(lastTelemetry?.score || 0);
  if (score > 0.55) {
    return json({ ok: false, error: "risk-too-high" }, 403);
  }

  const token = makePreclearanceToken({
    sub: fpKey,
    ip,
    exp: Date.now() + 30 * 60 * 1000,
    scopes: Array.isArray(body.scopes) ? body.scopes.slice(0, 10) : ["/"]
  });

  return json({ ok: true, token, expiresInSec: 1800 });
};
