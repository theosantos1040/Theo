import { send, getSession, deleteSession, clearCookies, reqId } from '../_lib.js';
export default async function handler(req, res) {
  const requestId = reqId(req);
  const session = await getSession(req);
  if (session) await deleteSession(session.id);
  send(res, 200, { ok: true, requestId }, { 'Set-Cookie': clearCookies() });
}
