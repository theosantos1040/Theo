import { send, getSession, reqId } from '../_lib.js';
export default async function handler(req, res) {
  const requestId = reqId(req);
  const session = await getSession(req);
  if (!session) return send(res, 401, { ok: false, requestId });
  send(res, 200, { ok: true, csrfToken: session.csrf, email: session.username, name: session.displayName, requestId });
}
