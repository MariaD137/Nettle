-- Stripe webhook idempotency and ordering.
--
-- webhook_events is a processed-event ledger: Stripe redelivers an event
-- whose original delivery didn't get a 2xx in time, using the SAME event id.
-- Inserting the id before processing and skipping on conflict makes a
-- redelivered event a no-op instead of double-applying a plan/status change.
--
-- users.last_subscription_event_at is a separate, per-account ordering guard:
-- Stripe does not guarantee webhook delivery order, so an out-of-order
-- delivery (e.g. an older customer.subscription.updated arriving after a
-- newer one) must not be allowed to overwrite a more current state with a
-- stale one. Stamped with the event's own `created` time (Stripe's clock,
-- not arrival time), compared strictly less-than so same-second events
-- (Stripe commonly fires several together) are not incorrectly rejected.

CREATE TABLE IF NOT EXISTS webhook_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  received_at TEXT NOT NULL
);

ALTER TABLE users ADD COLUMN last_subscription_event_at TEXT;
