# Frontend (React + Vite + TypeScript)

Open https://localhost and sign in as `admin`, `viewerA` or `viewerB` (passwords are in `.env`).

| Page | What it shows |
|------|---------------|
| **Overview** | KPI tiles (events, failed logins, high severity, open alerts), events over time (bars), **donuts** for sources and severity, and top IPs, countries, users and event types. Tiles, slices, bars and rows open a pre-filled search. |
| **Search** | Every `/api/events` filter. Clicking a row opens a side panel with the fields grouped (overview, network, identity, cloud), the tags, and the original log (`raw`). Results load 100 at a time. |
| **Alerts** | Open / acknowledged / all. "Events" opens the failed logins behind an alert; admins can acknowledge. |
| **Rules** | The detection rules with this tenant's settings. Admins switch a rule on/off and change its threshold; viewers see them read-only. |
| **API keys** (admin) | Create a key per sending system (shown once, with a Copy button) and revoke it. Hidden from viewers. |
| **Add logs** | Upload a log file (drag and drop; the log type is guessed from the file name and can be changed), with a plain-words result and a link to the new events. Plus copy-ready commands for the HTTP API and syslog. Upload is admin only; viewers see the commands. |

The layout is a sidebar for the pages (with a live count of open alerts) plus a **top bar** for
account-level controls, like most web apps:
- **Tenant**: admins get a "Viewing demoB ▾" menu that shows the current tenant with a ✓ and marks
  their default. The button is outlined whenever they're not on their default tenant. The choice
  survives a reload (per browser tab) and is cleared on sign-out. Viewers see their tenant, which they can't change.
  Every page subtitle names the tenant being shown.
- **Light/dark switch**: two states, sun and moon. The first visit follows the OS setting; after that the choice is remembered.
- **Profile menu**: name, role, read-only note for viewers, and Sign out.

Below 900 px the sidebar becomes a row of tabs above the top bar.

## Design decisions
- **No router library.** Pages are chosen by the URL hash (`#/events?src_ip=...`), so search
  filters live in the URL and links from the dashboard or alerts land on a ready-made search.
- **The token is kept in `localStorage`, so a reload keeps you signed in.** Trade-off: an XSS bug could read it. An
  httpOnly cookie avoids that but needs CSRF protection; acceptable for this demo. Any 401
  (expired token) returns to the login page.
- **Charts are kept simple on purpose** (`components/Charts.tsx`):
  - **events over time** are bars in one colour (time reads best as bars or a line);
  - **shares of a whole** are donuts: sources (the biggest four, the rest folded into "Other") and
    severity. A donut never has more than 5 slices, has 2px gaps between slices, the total in the
    middle, and a legend that names every slice with its count and percentage, so nothing relies on colour;
  - donut colours are ordered one-hue ramps checked with a palette validator (lightness order, step
    gaps, contrast with the card): **ink shades** for sources (darkest = biggest share) and a **red
    ramp** for critical/high/medium. Routine "low" is neutral grey, so red always means "look at this";
  - a **one-sentence takeaway** above each chart ("Firewall sends the most: 325 of 1,415 events (23%)");
  - hover for details, and **Show table** for the exact numbers.

  Earlier versions had stacked severity layers, a heatmap and sparklines. They were removed
  because they took longer to read than the question they answered.
- KPI tiles compare with the previous period of the same length ("12% more than the 24 hours before"),
  or say "Nothing in the 24 hours before" instead of showing an infinite percentage.
- **Severity and status pills** use a dot *and* the word (Critical/High/Medium/Low, Open/Acknowledged), never colour alone.
- **Plain language** for non-specialists:
  - card titles are questions or plain statements ("How serious are they?", "Where events come from");
  - source codes and tags show as words ("Active Directory", "Failed sign-in");
  - the side panel uses readable field names;
  - the alerts page explains the rule in one sentence.
  The technical values are still what the API receives, and appear as tooltips.
- **Layout**:
  - KPI tiles are always 4 or 2 across, never 3 + 1;
  - cards in a row have equal height, with footers pinned to the bottom;
  - the search table keeps 5 columns (source and flags sit under the event name), so it fits a laptop screen;
  - alerts are cards rather than a wide table.
- **Icons** are a small inline SVG set (`components/Icon.tsx`); no icon library.
- **Loading and empty states**: skeleton placeholders while loading, and a short explanation when there is nothing to show.
- **Warm minimal theme**:
  - light mode is a cream page, white cards, ink text and black buttons; dark mode is warm charcoal with cream text;
  - bars are charcoal (light gray in dark mode);
  - **colour is reserved for warnings**: red for alerts, critical and failed sign-ins, amber for high severity.
    Low and medium are neutral grey, so the red things stand out.
  - All colours are CSS tokens in `src/styles.css`. Charts read the computed tokens (SVG attributes
    can't use `var()`) and update when the theme changes.
- **Times** are stored in UTC and shown in the viewer's local time zone.
- **Login page**: a split screen. On the left, a dark product panel with a slowly scrolling sample
  log stream (decoration only, hidden from screen readers, and still if the system asks for reduced
  motion); on the right, a plain form with a show/hide password button. On phones only the form shows.

## Development
In Docker the app is built to static files and served by a small Caddy (`frontend/Caddyfile`).
For hot reload, run `npm install && npm run dev`; it proxies `/api` and `/health` to `localhost:8000`.
