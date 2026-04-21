# ASO Shield v3.1 for Vercel

Deploy on Vercel.

Important:
- configure `ASO_SESSION_SECRET`
- configure Vercel KV for persistence in production

Routes:
- `/`
- `/app/`
- `/admintheoasosecureo/`

API:
- `/api/health`
- `/api/challenge/mouse`
- `/api/challenge/mouse-verify`
- `/api/user/signup`
- `/api/user/login`
- `/api/user/session`
- `/api/user/logout`
- `/api/user/keys`
- `/api/client/start`
- `/api/protect/verify`

Enable Vercel Firewall, BotID, WAF rate limiting, and Attack Challenge Mode in the dashboard for best protection.
