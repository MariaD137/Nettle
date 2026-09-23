import { runDetection } from "./detection";
import type { StoredEvent } from "./types";

/**
 * Decouples detection from event ingestion (master spec Phase G / the
 * "Tier 2 processes events synchronously, in-process, with no queue" gap in
 * backend/README.md).
 *
 * Before this: `POST /api/events` called `await runDetection(...)` inline,
 * so the response to the customer's monitoring middleware didn't complete
 * until detection's read over the recent-events window (and any alert
 * writes it triggered) had finished. A busy monitored app sending one event
 * per request it served turned into a burst of synchronous SQLite work
 * blocking the ingestion endpoint's own response — exactly the problem the
 * README's known-gaps section calls out.
 *
 * `enqueueDetection` fires and returns immediately; the route responds as
 * soon as the event is durably recorded, and detection for that event runs
 * afterward, off the request's critical path. Jobs are processed serially
 * (one `runDetection` call at a time) rather than concurrently — not a
 * throughput compromise here, since `runDetection` itself is cheap, but a
 * correctness one: `hasRecentAlert`'s cooldown check only prevents a
 * duplicate alert if the previous alert's write has already landed, so
 * running two jobs for the same project concurrently could both pass the
 * cooldown check before either write completes and double-fire an alert.
 * Serializing the whole queue avoids that without needing per-project
 * locking.
 *
 * This is deliberately still in-process, not a real durable queue
 * (SQS/Kinesis) — the README explicitly calls for adding one only "once
 * there's real traffic to justify it," and `node:sqlite` being
 * single-instance today means a durable cross-instance queue wouldn't
 * change anything until that's solved too. What changes here is narrowly
 * what the known gap describes: detection no longer runs on the request's
 * critical path. The tradeoff to know about: this queue is memory-only, so
 * an in-flight (enqueued-but-not-yet-processed) detection job is lost on a
 * process restart. That's an acceptable loss — the event that triggered it
 * is already durably in the `events` table by the time it's enqueued, so
 * this only risks a missed detection pass for that one event, never lost
 * event data.
 */

let tail: Promise<void> = Promise.resolve();
let pending = 0;

export function enqueueDetection(projectId: string, event: StoredEvent): void {
  pending++;
  tail = tail
    .then(() => runDetection(projectId, event))
    .catch((err) => {
      console.error(`Detection failed for project ${projectId}, event ${event.id}:`, err);
    })
    .then(() => {
      pending--;
    });
}

/** How many detection jobs are enqueued or in flight right now. */
export function pendingDetectionJobs(): number {
  return pending;
}

/**
 * Resolves once every detection job enqueued so far (including ones
 * enqueued by an in-flight job's own completion, if any) has finished.
 * Test-only — production code never awaits the queue, since the whole
 * point is not blocking on it.
 */
export async function flushDetectionQueue(): Promise<void> {
  while (pending > 0) {
    await tail;
  }
}
