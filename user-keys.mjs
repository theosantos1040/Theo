import { json, getSession, strictJson, normalizeIdentifier, getSecurityStore, generateKeyRecord, maybeSendToSiem, planThresholds } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

const allowedPlans = new Set(["BASIC", "PRO", "ENTERPRISE"]);

export default async (req) => {
  const session = await getSession(req);
  if (!session || session.role !== "user") return json({ ok: false, error: "unauthorized" }, 401);

  const store = await getSecurityStore();
  const key = `userkeys:${session.userId}`;

  if (req.method === "GET") {
    return json({ ok: true, items: (await store.getJSON(key)) || [] });
  }

  if (req.method === "POST") {
    const csrf = req.headers.get("x-csrf-token");
    if (!csrf || csrf !== session.csrf) return json({ ok: false, error: "csrf" }, 403);

    const body = await strictJson(req);
    if (!body) return json({ ok: false, error: "bad-json" }, 400);

    const label = normalizeIdentifier(body.label || "Minha key", 120);
    const plan = String(body.plan || "BASIC").toUpperCase();
    const findings = inspectStrings([label, plan]);
    if (findings.length) return json({ ok: false, error: "malicious-input" }, 403);
    if (!allowedPlans.has(plan)) return json({ ok: false, error: "invalid-plan" }, 400);

    const items = (await store.getJSON(key)) || [];
    const item = { ...generateKeyRecord(label, session.username), plan, thresholds: planThresholds(plan) };
    items.unshift(item);
    await store.setJSON(key, items);
    await store.setJSON(`publickey:${item.publicId}`, { userId: session.userId, plan, secret: item.secret, label: item.label });
    await maybeSendToSiem({ type: "user_key_generated", userId: session.userId, email: session.username, label, plan, ts: Date.now() });
    return json({ ok: true, item }, 201);
  }

  return json({ ok: false, error: "method-not-allowed" }, 405);
};
