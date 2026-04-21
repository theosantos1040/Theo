import { json, getSession, strictJson, normalizeIdentifier, listKeys, saveKeys, generateKeyRecord, maybeSendToSiem } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

export default async (req) => {
  const session = await getSession(req);
  if (!session) return json({ ok: false, error: "unauthorized" }, 401);

  if (req.method === "GET") {
    const items = await listKeys();
    return json({ ok: true, items });
  }

  if (req.method === "POST") {
    const csrf = req.headers.get("x-csrf-token");
    if (!csrf || csrf !== session.csrf) return json({ ok: false, error: "csrf" }, 403);

    const body = await strictJson(req);
    if (!body) return json({ ok: false, error: "bad-json" }, 400);

    const label = normalizeIdentifier(body.label || "ASO Key", 120);
    const findings = inspectStrings([label]);
    if (findings.length) return json({ ok: false, error: "malicious-input" }, 403);

    const items = await listKeys();
    const item = generateKeyRecord(label, session.username);
    items.unshift(item);
    await saveKeys(items);
    await maybeSendToSiem({ type: "key_generated", actor: session.username, label: item.label, id: item.id, ts: Date.now() });
    return json({ ok: true, item }, 201);
  }

  return json({ ok: false, error: "method-not-allowed" }, 405);
};
