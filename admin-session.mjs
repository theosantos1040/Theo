import { json, getSession } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "GET") return json({ ok: false, error: "method-not-allowed" }, 405);
  const session = await getSession(req);
  if (!session) return json({ ok: false }, 401);
  return json({ ok: true, username: session.username, csrfToken: session.csrf });
};
