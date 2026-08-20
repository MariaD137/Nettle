/**
 * In-memory registry bridging a launched Fargate scan task back to the
 * `Promise` its caller is awaiting. Deliberately process-local, same
 * tradeoff jobs/scanJobs.ts's own job map already makes: a server restart
 * drops in-flight scans, acceptable for something a caller can resubmit,
 * and consistent with there being no persistent job queue (Redis, SQS)
 * anywhere else in this app yet.
 *
 * The callback token is the actual authorization boundary for
 * POST /api/internal/scan-tasks/:jobId/result|error (see
 * routes/internal.routes.ts) — a random, single-use, per-job secret, never
 * a database credential or any other application secret the task doesn't
 * need. It's consumed (the whole registry entry deleted) on first valid
 * use, so a replayed callback is rejected.
 */
import crypto from "crypto";
import type { ScanReport } from "../scanner/types";

interface PendingScan {
  callbackToken: string;
  resolve: (report: ScanReport) => void;
  reject: (err: Error) => void;
  timeoutHandle: NodeJS.Timeout;
}

const pending = new Map<string, PendingScan>();

export function newCallbackToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Registers a jobId as awaiting a Fargate task's callback. Returns a
 * Promise that resolves with the ScanReport on a valid `resolvePendingScan`
 * call, rejects on `rejectPendingScan`, or rejects on its own after
 * `timeoutMs` if neither ever arrives (task launch failure with no
 * callback, task hung past its own watchdog, network partition, etc).
 */
export function registerPendingScan(jobId: string, callbackToken: string, timeoutMs: number): Promise<ScanReport> {
  if (pending.has(jobId)) {
    throw new Error(`A scan is already pending for job ${jobId}`);
  }
  return new Promise<ScanReport>((resolve, reject) => {
    const timeoutHandle = setTimeout(() => {
      pending.delete(jobId);
      reject(new Error(`Scan task for job ${jobId} did not report back within ${timeoutMs}ms`));
    }, timeoutMs);
    timeoutHandle.unref();
    pending.set(jobId, { callbackToken, resolve, reject, timeoutHandle });
  });
}

/**
 * Validates the presented token against what was issued for this jobId,
 * constant-time, and — only on a match — consumes the pending entry and
 * resolves/rejects its promise. Returns false for an unknown jobId or a
 * wrong token (including a length mismatch), the same "reject, don't
 * distinguish why" shape as internal.routes.ts's existing cron-secret check.
 */
function claimPending(jobId: string, presentedToken: string): PendingScan | null {
  const entry = pending.get(jobId);
  if (!entry) return null;

  const presented = Buffer.from(presentedToken);
  const expected = Buffer.from(entry.callbackToken);
  const valid =
    presented.length === expected.length && crypto.timingSafeEqual(presented, expected);
  if (!valid) return null;

  pending.delete(jobId);
  clearTimeout(entry.timeoutHandle);
  return entry;
}

export function resolvePendingScan(jobId: string, presentedToken: string, report: ScanReport): boolean {
  const entry = claimPending(jobId, presentedToken);
  if (!entry) return false;
  entry.resolve(report);
  return true;
}

export function rejectPendingScan(jobId: string, presentedToken: string, message: string): boolean {
  const entry = claimPending(jobId, presentedToken);
  if (!entry) return false;
  entry.reject(new Error(message));
  return true;
}

/** Test-only: drops all pending entries between test files. */
export function _resetPendingScansForTests(): void {
  for (const entry of pending.values()) clearTimeout(entry.timeoutHandle);
  pending.clear();
}
