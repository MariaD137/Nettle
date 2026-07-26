# Nettle — frontend

The dashboard: sign up, create a project, upload code for a Tier 1 scan and
read the report, view Tier 2 alerts and scan history, embed the trust badge,
and upgrade to a paid plan. Real, working React app talking to the real
backend API — not a mockup.

## Run it

```bash
npm install
npm run dev     # http://localhost:5173, expects the backend on :8080
```

Point it at a different backend with `VITE_API_BASE_URL`:

```bash
VITE_API_BASE_URL=https://api.example.com npm run dev
```

## Validated how

Every page was driven with a real headless browser (Playwright) against a
real running backend, not just type-checked: sign up, create a project,
upload the flawed sample-app fixture from the backend's own test suite,
confirm the report renders all findings, confirm the badge pill updates
from "not yet scanned" to "issues found" after that scan, confirm the
alerts/history tabs load, and confirm an unconfigured-billing checkout
fails gracefully (a clear error, not a broken page) rather than crashing.

## Pages

| Route | What it does |
|---|---|
| `/login` | Combined sign-up/log-in form |
| `/` | Project list with live badge status per project, create-project form |
| `/projects/:id` | Tabs: Overview (badge embed + API key + monitor snippet), Scan (upload + report), Alerts, History, Billing |
| `/billing/success`, `/billing/cancelled` | Stripe Checkout redirect targets |

## Known gaps

- **No password reset flow.** Sign up and log in only.
- **No rate limiting on the auth endpoints**, front or back end — same gap
  the backend README already flags for the API generally.
- **Session token lives in `localStorage`**, not an httpOnly cookie — fine
  given every route requires an explicit bearer token already (no
  cookie-based CSRF surface), but an XSS in this app would be able to read
  it. Worth revisiting once there's more surface area for that (e.g.
  third-party scripts).
- **No deployment/hosting set up yet.** This isn't part of `infra/` yet —
  needs its own static hosting (S3+CloudFront, Vercel, or similar) and a
  real `VITE_API_BASE_URL` pointed at the deployed backend.
