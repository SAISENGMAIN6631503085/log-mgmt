# Frontend (React + Vite + TypeScript)

Open https://localhost and sign in as `admin`, `viewerA` or `viewerB` (passwords are in `.env`).

| Page | What it shows |
|------|---------------|
| **Overview** | A KPI strip (events, failed logins, high severity, open alerts; one surface split by hairlines, with changes written as "↑ 12% more" or "↑ 72× more vs. previous 24 h"), events over time (bars), **donuts** for sources and severity, and top IPs, countries, users and event types. Tiles, slices, bars and rows open a pre-filled search. |
| **Search** | Search first: one big text box, the time range and a Search button. Source, severity and kind sit underneath and apply as soon as they're picked; IP, user, computer, country and event name are under **More filters**. Every active filter shows as a chip you can remove on its own. Clicking a row opens a side panel with the fields grouped, the flags, and the original log (`raw`). Results load 100 at a time. |
| **Alerts** | A triage queue, newest first and grouped by day. A sentence on top sums up what's open ("22 open alerts: 3 critical, 15 high…, the oldest has waited 25 hours"); chips filter by rule. Each alert's headline says what happened in plain words, a coloured rail on the left shows how serious it is, and Started / Lasted / Seen in / Notified give the facts. **Investigate** opens the events behind it; admins can **Acknowledge**, and handled alerts turn grey. |
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
- **Tables are built to be scanned**:
  - "Top N" tables show a **rank**, a readable name with **one line of context** under it (an IP's
    country or "Private network", a user's domain, an event's raw code), a thin **share bar**, the
    count with its **% of all events**, and failed sign-ins as a **red badge only when there are any**;
  - event codes are shown in plain words ("logon_success" → "Logon success", "UserLoggedIn" →
    "User logged in"); the raw value stays in tooltips, the side panel and every search/API call;
  - in Search, each IP has its country (or "Private network") underneath.
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
- **"Graphite & Signal" theme** (a log tool is used like an instrument panel, so it should feel precise):
  - a **dark graphite sidebar** in both modes frames the app, with a teal marker on the active page;
  - light mode is a cool grey page with white surfaces and graphite text; dark mode is deep graphite;
  - **signal teal** is the one accent: buttons, links, toggles, focus rings, chart bars and the sources donut;
  - **red is reserved for warnings**: alerts, critical/high/medium severity and failed sign-ins. Routine
    things are neutral grey, so red always means "look at this";
  - type is **IBM Plex Sans** (text) and **IBM Plex Mono** (IPs, codes, log lines), bundled with
    `@fontsource` so the appliance works offline (Latin subset, 3 + 2 weights);
  - the donut ramps (teal for sources, red for severity) were re-checked with the palette validator
    against the new light and dark surfaces;
  - All colours are CSS tokens in `src/styles.css`. Charts read the computed tokens (SVG attributes
    can't use `var()`) and update when the theme changes.
- **Times** are stored in UTC and shown in the viewer's local time zone.
- **Login page**: a split screen. On the left, a dark product panel with a slowly scrolling sample
  log stream (decoration only, hidden from screen readers, and still if the system asks for reduced
  motion); on the right, a plain form with a show/hide password button. On phones only the form shows.

## Development
In Docker the app is built to static files and served by a small Caddy (`frontend/Caddyfile`).
For hot reload, run `npm install && npm run dev`; it proxies `/api` and `/health` to `localhost:8000`.
