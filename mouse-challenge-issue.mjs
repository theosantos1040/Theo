import crypto from "node:crypto";
import { json, getSecurityStore } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "GET") return json({ ok: false, error: "method-not-allowed" }, 405);
  const id = crypto.randomUUID();
  const nonce = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000;
  const store = await getSecurityStore();
  await store.setJSON(`mousechallenge:${id}`, { nonce, expiresAt });
  return json({ ok: true, challengeId: id, nonce, expiresAt });
};
