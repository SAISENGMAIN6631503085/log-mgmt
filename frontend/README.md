# Frontend (React + Vite + TypeScript)

Open https://localhost and sign in as `admin`, `viewerA` or `viewerB` (passwords are in `.env`).

| Page | What it shows |
|------|---------------|
| **Dashboard** | KPI tiles (events, failed logins, high severity, open alerts), events over time, by source, by severity, top source IPs, top event types. Tiles, bars and table rows link to a pre-filled search. |
| **Search** | Every `/api/events` filter. Click a row to see all normalized fields and the original log (`raw`). Results load 100 at a time ("Load more"). |
| **Alerts** | Open or acknowledged alerts. "Events" opens the failed logins behind an alert; admins can acknowledge. |

Admins get a **tenant switcher** in the top bar (it sends `?tenant=`); viewers just see their tenant.

## Design decisions
- **No router library.** Pages are chosen by the URL hash (`#/events?src_ip=...`), so search
  filters live in the URL and links from the dashboard or alerts land on a ready-made search.
- **The token is kept in `localStorage`, so a reload keeps you signed in.** Trade-off: an XSS bug could read it. An
  httpOnly cookie avoids that but needs CSRF protection; acceptable for this demo. Any 401
  (expired token) returns to the login page.
- **Charts** (Recharts) follow one set of rules:
  - Every chart is a single series in one accent colour, so the card title names it and no legend is needed.
  - Bars have rounded data ends, recessive grid and axes, and a hover tooltip.
  - Each chart has a **Table** toggle with the exact numbers.
  - Events over time is drawn as columns, not a smooth line, because each value is a count for a fixed bucket.
- **Severity badges** use a dot *and* the word (critical/high/medium/low), never colour alone.
- **Light and dark mode** follow the OS. Colours are CSS tokens in `src/styles.css`; charts read
  the computed tokens (SVG attributes can't use `var()`) and update when the theme changes.
- **Times** are stored in UTC and shown in the viewer's local time zone.

## Development
In Docker the app is built to static files and served by a small Caddy (`frontend/Caddyfile`).
For hot reload, run `npm install && npm run dev`; it proxies `/api` and `/health` to `localhost:8000`.
