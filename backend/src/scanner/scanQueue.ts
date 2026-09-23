import { runScan } from "./index";
import { completeQueuedScan, failQueuedScan, markScanStatus } from "../patrol/scans";

/**
 * Decouples project-tied scan execution from the HTTP request that triggers
 * it (master spec: "scans no longer depend on the HTTP request remaining
 * open for the full scan"), using the same in-process async queue pattern
 * already established for continuous-monitoring detection — see
 * patrol/detectionQueue.ts's comment for the full reasoning behind that
 * choice over reaching for real AWS infrastructure (SQS/Fargate/etc.)
 * before there's real traffic to justify it.
 *
 * Scope, stated honestly: this decouples the *client* from the scan's
 * duration — POST /api/scans returns as soon as the scan record is created,
 * not after the scan runs. It does NOT make the scan itself non-blocking
 * within the Node process: scanner/index.ts's runScan() calls out to
 * Semgrep and other checks via execFileSync (a deliberately synchronous,
 * bounded-timeout subprocess call — see scanner/controls/checks/
 * semgrepControl.ts), which blocks the event loop for its duration exactly
 * as it always has. Converting the scanner pipeline itself to non-blocking
 * subprocess execution would be a much larger change touching every check
 * that shells out, and isn't what was asked for here. What changes is
 * real and matches the stated problem: no HTTP connection, load balancer,
 * or CI client has to stay attached for the scan's duration anymore, and a
 * scan's own timeout/failure can no longer take an in-flight HTTP request
 * down with it.
 *
 * Jobs run strictly serially (like detectionQueue.ts), which costs nothing
 * here beyond what already exists: because runScan() blocks synchronously
 * while it runs, "concurrent" jobs in a single Node process could not
 * actually execute in parallel regardless of how the queue were structured
 * — a second job's code simply cannot run until the first job's blocking
 * call returns. Serial processing is therefore not a throughput compromise,
 * just an honest match to the actual execution model.
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
    const report = runScan(job.scanRoot);
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
 * A failure inside one job (a throw from runScan, or from the status
 * updates around it) is caught here so it can never break the chain for
 * jobs queued after it — same resilience property detectionQueue.ts's own
 * tests verify for its queue.
 */
export function enqueueScan(job: ScanJobInput): void {
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

// Known, disclosed limitation (matches detectionQueue.ts's own documented
// tradeoff): this queue is memory-only. If the process crashes or restarts
// while a job is queued or mid-SCANNING, that job is lost — the row is left
// at CREATED or SCANNING with no automatic recovery, since there is no real
// message queue here to redeliver it. The scan record itself is not
// corrupted (the client can retrigger a scan for the project), but nothing
// currently sweeps and fails stale in-flight rows. A real queue backend
// (SQS + a separate worker) would close this gap — deliberately not added
// speculatively here, same reasoning as the monitoring detection queue.
