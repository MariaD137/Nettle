import { db, newId } from "../db/index";

// Stripe explicitly documents webhook delivery as at-least-once, so a
// redelivered event id must be recognized and skipped rather than
// re-applying its side effects (a second "your payment failed" email, a
// duplicate payment_failures row, etc).
//
// This used to be a separate check-then-mark: isStripeEventProcessed()
// (a SELECT) at the top of the webhook handler, then
// markStripeEventProcessed() (an INSERT OR IGNORE) after all side effects
// ran. That left a real TOCTOU race — two genuinely concurrent deliveries
// of the same event id (Stripe's own docs describe redelivery as
// plausible, and the handler itself awaits e.g. sendEmail() between the
// check and the mark) could both pass the SELECT before either reached the
// INSERT, both running the side effects.
//
// claimStripeEvent() closes that window by doing the INSERT *first*, as
// the sole atomic operation deciding who gets to process this event — not
// a second confirmation of a decision already made. stripe_events.event_id
// is a PRIMARY KEY, so SQLite itself enforces that only one INSERT for a
// given id can ever succeed; the loser gets a real constraint violation,
// not a race-prone read. Call this once, synchronously, immediately after
// signature verification and before any side effect or `await` — node:sqlite
// executes each statement synchronously, so as long as nothing yields the
// event loop between "verified" and "claimed," two concurrent requests for
// the same event id cannot both observe "not yet claimed."
export function claimStripeEvent(eventId: string, eventType: string): boolean {
  try {
    db.prepare(
      "INSERT INTO stripe_events (event_id, event_type, processed_at) VALUES (?, ?, ?)"
    ).run(eventId, eventType, new Date().toISOString());
    return true;
  } catch (err) {
    // SQLITE_CONSTRAINT (unique/primary key violation) means another
    // request already claimed this exact event id — a real duplicate, not
    // an error to surface. Anything else is a genuine failure and should
    // propagate.
    if (err instanceof Error && /UNIQUE constraint failed|SQLITE_CONSTRAINT/i.test(err.message)) {
      return false;
    }
    throw err;
  }
}

export interface PaymentFailureRecord {
  id: string;
  userId: string;
  stripeInvoiceId: string;
  amountDue: number | null;
  currency: string | null;
  failureReason: string | null;
  occurredAt: string;
  resolvedAt: string | null;
}

export function recordPaymentFailure(input: {
  userId: string;
  stripeInvoiceId: string;
  amountDue?: number | null;
  currency?: string | null;
  failureReason?: string | null;
}): void {
  db.prepare(
    `INSERT INTO payment_failures (id, user_id, stripe_invoice_id, amount_due, currency, failure_reason, occurred_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    newId(),
    input.userId,
    input.stripeInvoiceId,
    input.amountDue ?? null,
    input.currency ?? null,
    input.failureReason ?? null,
    new Date().toISOString()
  );
}

export function getPaymentFailures(userId: string, limit: number = 20): PaymentFailureRecord[] {
  const rows = db
    .prepare(
      `SELECT id, user_id, stripe_invoice_id, amount_due, currency, failure_reason, occurred_at, resolved_at
       FROM payment_failures WHERE user_id = ? ORDER BY occurred_at DESC LIMIT ?`
    )
    .all(userId, limit) as unknown as {
    id: string;
    user_id: string;
    stripe_invoice_id: string;
    amount_due: number | null;
    currency: string | null;
    failure_reason: string | null;
    occurred_at: string;
    resolved_at: string | null;
  }[];

  return rows.map((r) => ({
    id: r.id,
    userId: r.user_id,
    stripeInvoiceId: r.stripe_invoice_id,
    amountDue: r.amount_due,
    currency: r.currency,
    failureReason: r.failure_reason,
    occurredAt: r.occurred_at,
    resolvedAt: r.resolved_at,
  }));
}
