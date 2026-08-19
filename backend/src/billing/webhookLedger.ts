import { db } from "../db";

// Stripe can and does deliver the same webhook event more than once (a
// retry after a slow or failed response looks identical to a fresh event).
// Recording processed event IDs lets the webhook handler apply each one
// exactly once instead of re-running side effects like plan activation.

export function isStripeEventProcessed(eventId: string): boolean {
  const row = db.prepare("SELECT 1 FROM processed_stripe_events WHERE event_id = ?").get(eventId);
  return !!row;
}

export function markStripeEventProcessed(eventId: string): void {
  db.prepare("INSERT OR IGNORE INTO processed_stripe_events (event_id, processed_at) VALUES (?, ?)").run(
    eventId,
    new Date().toISOString()
  );
}
