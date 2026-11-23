import { json, getSession, deleteSession, clearSessionHeaders } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const session = await getSession(req);
  if (session) await deleteSession(session.id);
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionHeaders() });
};
