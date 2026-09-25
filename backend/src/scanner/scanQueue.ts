import { runScan } from "./index";
import { completeQueuedScan, failQueuedScan, markScanStatus } from "../patrol/scans";
import { isIsolatedExecutionConfigured, runScanIsolated } from "./isolatedExecution";
import { isDurableQueueConfigured, enqueueScanDurable } from "./durableQueue";

/**
 * Decouples project-tied scan execution from the HTTP request that triggers
 * it (master spec: "scans no longer depend on the HTTP request remaining
 * open for the full scan"), using the same in-process async queue pattern
 * already established for continuous-monitoring detection — see
 * patrol/detectionQueue.ts's comment for the full reasoning.
 *
 * What this queue itself does and doesn't do, stated honestly: it decouples
 * the *client* from the scan's duration — POST /api/scans returns as soon
 * as the scan record is created, not after the scan runs — and it processes
 * jobs strictly serially, same as detectionQueue.ts.
 *
 * Whether the scan itself runs isolated or in-process is a separate
 * question this queue delegates entirely to isolatedExecution.ts's
 * isIsolatedExecutionConfigured() (see runJob below):
 *   - Configured (SCAN_ECS_* env vars present — production, once
 *     scan-worker-stack.ts is deployed): the scan runs inside its own ECS
 *     Fargate task — a real process/container/network boundary, with none
 *     of the API's own credentials. See isolatedExecution.ts and
 *     scan-worker-stack.ts for the full design.
 *   - Not configured (every test, local development, this sandbox — no AWS
 *     ECS config available): falls back to calling runScan() directly,
 *     in-process. scanner/index.ts's runScan() calls out to Semgrep and
 *     other checks via execFileSync, which blocks the Node event loop for
 *     its duration exactly as it always has in this fallback path — this
 *     is the same disclosed, unsandboxed behavior scanQueue.ts always had
 *     before isolatedExecution.ts existed, kept exactly as-is for any
 *     environment that hasn't deployed the isolated worker.
 *
 * Serial processing costs nothing in the in-process fallback (runScan()
 * blocks synchronously, so "concurrent" jobs couldn't actually run in
 * parallel in one Node process regardless of queue structure) and is a
 * genuine (if modest) throughput ceiling in the isolated path, where the
 * API dispatches and polls one Fargate task at a time rather than several
 * concurrently — a deliberate simplicity trade-off for this pass, not a
 * hard architectural limit; scan-worker-stack.ts's cluster has no fixed
 * concurrency cap of its own.
 */

export interface ScanJobInput {
  scanId: string;
  scanRoot: string;
  /** Called after the job finishes (success or failure) so the caller can clean up its own temp directories. */
  cleanup: () => void;
}

let tail: Promise<void> = Promise.resolve();
let pending = 0;

async function runJob(job: ScanJobInput): Promise<void> {
  await markScanStatus(job.scanId, "SCANNING");
  try {
    // Isolated execution (scanner/isolatedExecution.ts) when configured —
    // true sandboxing, a separate ECS Fargate task/process/network path
    // with none of the API's own credentials (see that file and
    // scan-worker-stack.ts). Falls back to the pre-existing in-process call
    // when it isn't (no AWS ECS config present — every test, local dev, and
    // this sandbox), so nothing about the existing, disclosed in-process
    // fallback's behavior changes for an environment that was never
    // configured for isolation in the first place.
    const report = isIsolatedExecutionConfigured() ? await runScanIsolated(job.scanId, job.scanRoot) : runScan(job.scanRoot);
    await completeQueuedScan(job.scanId, report);
  } catch (err) {
    const message = (err as Error).message;
    console.error(`[scan-queue] scan ${job.scanId} failed: ${message}`);
    await failQueuedScan(job.scanId, message);
  } finally {
    try {
      job.cleanup();
    } catch (cleanupErr) {
      // A cleanup failure (e.g. a permissions quirk on the extracted tree)
      // must not be mistaken for a scan failure — it's already logged
      // separately here rather than folded into failQueuedScan's message.
      console.error(`[scan-queue] cleanup failed for scan ${job.scanId}: ${(cleanupErr as Error).message}`);
    }
  }
}

/**
 * Enqueues a scan job and returns immediately — the caller (routes/
 * scans.routes.ts) has already responded to the client with the scan's id
 * and CREATED status by the time this settles.
 *
 * Delegates to durableQueue.ts (SQS-backed, survives an API restart) when
 * SCAN_QUEUE_URL/SCAN_WORKSPACE_BUCKET_NAME are configured — production,
 * once scan-worker-stack.ts's queue is deployed. Falls back to the
 * in-memory path below otherwise (every test, local dev, this sandbox),
 * unchanged from before durableQueue.ts existed. A failure enqueueing
 * durably (an S3/SQS error, not a scan failure — those are handled inside
 * pollDurableQueueOnce) still leaves a real FAILED record rather than a
 * scan stuck at CREATED forever.
 *
 * A failure inside one in-memory job (a throw from runScan, or from the
 * status updates around it) is caught here so it can never break the chain
 * for jobs queued after it — same resilience property detectionQueue.ts's
 * own tests verify for its queue.
 */
export function enqueueScan(job: ScanJobInput): void {
  if (isDurableQueueConfigured()) {
    enqueueScanDurable(job).catch((err) => {
      console.error(`[scan-queue] durable enqueue failed for scan ${job.scanId}: ${(err as Error).message}`);
      failQueuedScan(job.scanId, (err as Error).message).catch(() => undefined);
      try {
        job.cleanup();
      } catch {
        // already best-effort
      }
    });
    return;
  }

  pending++;
  tail = tail
    .then(() => runJob(job))
    .catch((err) => {
      // runJob itself catches scan failures; reaching here means something
      // in the bookkeeping around it (markScanStatus, the DB) threw. Best
      // effort: still try to leave the row in a real FAILED state and clean
      // up, rather than leaving it stuck at CREATED/SCANNING forever.
      console.error(`[scan-queue] unexpected queue error for scan ${job.scanId}: ${(err as Error).message}`);
      return failQueuedScan(job.scanId, (err as Error).message)
        .catch(() => undefined)
        .finally(() => {
          try {
            job.cleanup();
          } catch {
            // already best-effort
          }
        });
    })
    .then(() => {
      pending--;
    });
}

/** How many scan jobs are enqueued or in flight right now. */
export function pendingScanJobs(): number {
  return pending;
}

/** Test-only: resolves once every enqueued scan job has finished. Production code never awaits the queue. */
export async function flushScanQueue(): Promise<void> {
  while (pending > 0) {
    await tail;
  }
}

// The in-memory path below is memory-only, same known, disclosed limitation
// detectionQueue.ts's own queue still has: if the process crashes or
// restarts while a job is queued or mid-SCANNING, that job is lost with no
// automatic recovery. That gap is now closed for any environment with
// SCAN_QUEUE_URL/SCAN_WORKSPACE_BUCKET_NAME configured — enqueueScan()
// above delegates to durableQueue.ts's SQS-backed queue instead, which
// survives a process restart (see that file). This in-memory path remains
// exactly as it always was for every environment without that config: every
// test, local development, and this sandbox.
