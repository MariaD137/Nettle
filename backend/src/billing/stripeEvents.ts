import { db, newId } from "../db/index";

// Stripe explicitly documents webhook delivery as at-least-once, so a
// redelivered event id must be recognized and skipped rather than
// re-applying its side effects (a second "your payment failed" email, a
// duplicate payment_failures row, etc).
export function isStripeEventProcessed(eventId: string): boolean {
  const row = db.prepare("SELECT 1 FROM stripe_events WHERE event_id = ?").get(eventId);
  return !!row;
}

export function markStripeEventProcessed(eventId: string, eventType: string): void {
  db.prepare(
    "INSERT OR IGNORE INTO stripe_events (event_id, event_type, processed_at) VALUES (?, ?, ?)"
  ).run(eventId, eventType, new Date().toISOString());
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
