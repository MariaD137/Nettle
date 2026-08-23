# Nettle 

Scans AI-built apps for the security, legal, and compliance gaps their
creators don't know to look for — then keeps watching for hackers after
they ship.

## Structure

- **`backend/`** — the Tier 1 "Dry Dock" scan engine + Tier 2 "Open Water"
  continuous monitoring, all as one API: hardcoded-secret detection (regex
  + Semgrep), a real bundled OSV vulnerability database, legal/policy and
  AI-disclosure checks, accounts/sessions, project/scan/alert persistence,
  the trust badge, and Stripe billing. Real, tested code — 53 automated
  tests, including end-to-end HTTP checks and a genuinely-signed Stripe
  webhook verification. See `backend/README.md`.
- **`frontend/`** — the dashboard: sign up, create a project, upload code
  for a scan and read the report, view alerts and scan history, embed the
  badge, upgrade to a paid plan. A real React app, browser-tested against
  the real backend with Playwright. See `frontend/README.md`.
- **`infra/`** — AWS CDK app: a network-isolated VPC (no NAT, no internet
  gateway), an App Runner service for the API, and a GitHub OIDC role for
  CI/CD. Scoped to what Tier 1 actually needs, not a copy of a bigger app's
  infrastructure. See `infra/README.md`.
- **`.github/workflows/`** — CI (lint + test on every PR touching
  `backend/` or `frontend/`) and deploy (build + push to ECR on push to
  `main`).

## What's real vs. what's still a known gap

Everything in the original "doesn't exist yet" list now exists as real,
tested code: Tier 2, the trust badge, a frontend, and a persistent data
store with accounts and billing. What's still genuinely open, in rough
priority order:

- **No Docker daemon in this sandbox to actually run `docker build`** —
  the image builds Python + pip + Semgrep into the runtime now; build it
  yourself once before deploying.
- **Billing is untested against a live Stripe account** — the webhook
  signature verification is real and tested, but there are no Stripe
  test-mode keys in this sandbox to run an actual checkout through.
- **Tier 1 has no sandboxing yet** — it runs static analysis on uploaded
  code directly on the API host. Real isolation (an ECS Fargate task per
  scan, or e2b/Modal) is the next real hardening step before this touches
  untrusted traffic at scale.
- **No password reset, no rate limiting on auth endpoints, no queue
  between Tier 2 intake and detection, `node:sqlite` doesn't work past one
  container instance.**

See `backend/README.md`'s "Known gaps" section and `infra/README.md`'s
"what's deliberately not here yet" for the full list and reasoning on each.
