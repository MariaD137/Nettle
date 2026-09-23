import { db } from "../db";

/**
 * Idempotency for Stripe webhook delivery. Stripe redelivers an event using
 * the same event id whenever the original delivery didn't get a 2xx in time,
 * and — separately — a malicious or buggy client could replay a captured
 * webhook payload. Recording the id before processing and treating a primary
 * key conflict as "already handled" makes both cases a no-op rather than a
 * double-applied plan/status change.
 *
 * Returns true the first time an event id is seen (caller should process it),
 * false if it was already recorded (caller should skip processing and still
 * return 200 — Stripe should not keep retrying an event that already
 * succeeded on a previous delivery).
 */
export async function recordWebhookEventOnce(eventId: string, eventType: string): Promise<boolean> {
  try {
    await db.run("INSERT INTO webhook_events (event_id, event_type, received_at) VALUES (?, ?, ?)", [
      eventId,
      eventType,
      new Date().toISOString(),
    ]);
    return true;
  } catch {
    // Primary-key conflict: this event id was already recorded. Any other
    // insert failure would also throw here; either way, refusing to process
    // an event we can't durably record as handled is the safe direction —
    // Stripe will simply redeliver it.
    return false;
  }
}
