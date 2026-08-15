# Payments Component

## Purpose

Handles subscription billing via Stripe. Users can upgrade from the free plan to pro or team plans.

## Location

- `backend/src/billing/stripeClient.ts` — Stripe SDK initialization
- `backend/src/routes/billing.routes.ts` — Checkout and webhook endpoints

## API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/billing/checkout-session` | Yes | Create Stripe Checkout Session |
| POST | `/api/billing/webhook` | No | Receive Stripe webhook events |

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `STRIPE_SECRET_KEY` | Yes | Stripe API authentication |
| `STRIPE_WEBHOOK_SECRET` | Yes | Webhook signature verification |
| `BILLING_SUCCESS_URL` | No | Redirect after successful checkout |
| `BILLING_CANCEL_URL` | No | Redirect after cancelled checkout |

## Database Tables

- `users.plan` — Current plan (`free`, `pro`, `team`)
- `users.stripe_customer_id` — Stripe customer identifier
- `users.subscription_status` — Stripe subscription status

## Dependencies

- `stripe` npm package
- Stripe webhook must be mounted before `express.json()` middleware (raw body needed for signature verification)

## External Services

- Stripe API (checkout sessions, customer management)
- Stripe Webhooks (subscription fulfillment)

## Tests

- `backend/test/billing.test.ts` — Auth requirements, error handling, webhook signature verification, subscription activation

## Common Failures

- Webhook signature mismatch: Wrong `STRIPE_WEBHOOK_SECRET` or body parsing order
- Checkout session 503: `STRIPE_SECRET_KEY` not set (returns 503 instead of crashing)
- Plan not updating: Webhook event type not handled

## How to Repair

```bash
git checkout -b fix/billing-<problem>
# Edit backend/src/billing/ or backend/src/routes/billing.routes.ts
NETTLE_DB_PATH=:memory: node --import tsx --test test/billing.test.ts
```

## Rollback

Billing changes are code-only. Stripe webhooks will retry failed deliveries. Revert the commit to roll back.
