import { json, strictJson, getSecurityStore, serviceTokenSign } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const store = await getSecurityStore();
  const entry = await store.getJSON(`mousechallenge:${body.challengeId}`);
  if (!entry) return json({ ok: false, error: "unknown-challenge" }, 404);
  if (Date.now() > entry.expiresAt) return json({ ok: false, error: "expired" }, 410);

  const stats = body.stats && typeof body.stats === "object" ? body.stats : {};
  const distance = Number(stats.distance || 0);
  const duration = Number(stats.duration || 0);
  const moves = Number(stats.moves || 0);

  const passed = distance >= 220 && duration >= 1200 && moves >= 12;
  if (!passed) return json({ ok: false, error: "mouse-challenge-failed" }, 403);

  const token = serviceTokenSign({
    type: "mouse_signup",
    challengeId: body.challengeId,
    exp: Date.now() + 10 * 60 * 1000
  });

  return json({ ok: true, token });
};
