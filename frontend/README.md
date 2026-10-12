# Frontend (React + Vite + TypeScript)

Built to static files in Docker and served by a small internal Caddy (`frontend/Caddyfile`);
the edge Caddy proxies to it. For hot-reload development: `npm install && npm run dev`
(proxies `/api` and `/health` to `localhost:8000`).
