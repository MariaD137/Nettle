/**
 * In-memory scan job queue and store. Scans that go through this path run
 * in a worker_thread (scanner/scanWorker.ts) instead of blocking the main
 * request — the point being genuine real-time progress and a real,
 * concurrency-limited queue, not a simulated one. This is deliberately
 * additive: the existing synchronous POST /api/scans* routes are untouched
 * and keep working exactly as before (the CLI and any direct API
 * integrations depend on that immediate-report contract) — this queue
 * backs a new, separate flow that only the web UI uses.
 *
 * State lives in this process's memory only. A server restart drops
 * in-flight and queued jobs — acceptable for a scan you can just resubmit,
 * and consistent with there being no persistent job infrastructure
 * (Redis, a jobs table) anywhere else in this app yet.
 */
import { Worker } from "worker_threads";
import path from "path";
import crypto from "crypto";
import { sourceScanSteps, URL_SCAN_STEPS, type ScanStepEvent } from "../scanner/index";
import type { ScanReport } from "../scanner/types";
import type { ScanWorkerInput, ScanWorkerMessage } from "../scanner/scanWorker";

export type ScanJobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ScanJobStepStatus = "pending" | "running" | "done";

export interface ScanJobStep {
  id: string;
  label: string;
  status: ScanJobStepStatus;
}

export interface ScanJob {
  id: string;
  status: ScanJobStatus;
  source: "upload" | "repo" | "url";
  steps: ScanJobStep[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  report: ScanReport | null;
  error: string | null;
  queuePosition: number | null;
}

interface ScanJobMeta {
  ownerUserId: string | null;
  projectId: string | null;
  billedUserId: string | null;
  onComplete?: (report: ScanReport) => void;
}

interface InternalJob {
  id: string;
  status: ScanJobStatus;
  steps: ScanJobStep[];
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  report: ScanReport | null;
  error: string | null;
  input: ScanWorkerInput;
  meta: ScanJobMeta;
  worker: Worker | null;
}

const jobs = new Map<string, InternalJob>();
const queue: string[] = [];
let runningCount = 0;

// Read at call time (not cached at module load) so tests can adjust
// concurrency per-test without needing to reload the module.
function maxConcurrent(): number {
  const raw = process.env.NETTLE_MAX_CONCURRENT_SCANS;
  const n = raw ? parseInt(raw, 10) : 2;
  return Number.isFinite(n) && n > 0 ? n : 2;
}

function stepsFor(input: ScanWorkerInput): ScanJobStep[] {
  const descriptors = input.mode === "url" ? URL_SCAN_STEPS : sourceScanSteps([], "");
  return descriptors.map((d) => ({ id: d.id, label: d.label, status: "pending" as const }));
}

function workerEntry(): { file: string; execArgv: string[] } {
  const scannerDir = path.join(__dirname, "..", "scanner");
  const compiled = __filename.endsWith(".js");
  return compiled
    ? { file: path.join(scannerDir, "scanWorker.js"), execArgv: [] }
    : { file: path.join(scannerDir, "scanWorker.ts"), execArgv: ["--require", "tsx/cjs"] };
}

export function createScanJob(input: ScanWorkerInput, meta: ScanJobMeta): ScanJob {
  const id = crypto.randomUUID();
  const job: InternalJob = {
    id,
    status: "queued",
    steps: stepsFor(input),
    createdAt: new Date().toISOString(),
    startedAt: null,
    finishedAt: null,
    report: null,
    error: null,
    input,
    meta,
    worker: null,
  };
  jobs.set(id, job);
  queue.push(id);
  tryDequeue();
  return toPublicJob(job);
}

function tryDequeue() {
  while (runningCount < maxConcurrent() && queue.length > 0) {
    const id = queue.shift()!;
    const job = jobs.get(id);
    // Job may have been cancelled while still queued.
    if (!job || job.status !== "queued") continue;
    startJob(job);
  }
}

function startJob(job: InternalJob) {
  runningCount++;
  job.status = "running";
  job.startedAt = new Date().toISOString();

  const { file, execArgv } = workerEntry();
  const worker = new Worker(file, { execArgv, workerData: job.input });
  job.worker = worker;

  worker.on("message", (message: ScanWorkerMessage) => {
    if (message.type === "progress") {
      applyProgress(job, message.event);
    } else if (message.type === "done") {
      finishJob(job, "completed", { report: message.report });
    } else if (message.type === "error") {
      finishJob(job, "failed", { error: message.message });
    }
  });

  worker.on("error", (err) => {
    finishJob(job, "failed", { error: err.message || String(err) });
  });

  worker.on("exit", (code) => {
    // A non-zero exit with no prior "done"/"error" message (e.g. the
    // process crashed outright) still needs to resolve the job so a poller
    // isn't left waiting forever.
    if (job.status === "running") {
      finishJob(job, "failed", { error: `Scan worker exited unexpectedly (code ${code})` });
    }
  });
}

function applyProgress(job: InternalJob, event: ScanStepEvent) {
  const step = job.steps[event.index];
  if (!step) return;
  step.status = event.type === "step-start" ? "running" : "done";
}

function finishJob(job: InternalJob, status: "completed" | "failed" | "cancelled", outcome: { report?: ScanReport; error?: string }) {
  if (job.status !== "running" && job.status !== "queued") return; // already resolved
  job.status = status;
  job.finishedAt = new Date().toISOString();
  job.report = outcome.report ?? null;
  job.error = outcome.error ?? null;
  if (status === "completed") {
    for (const step of job.steps) step.status = "done";
  }
  if (job.worker) {
    runningCount--;
    job.worker.removeAllListeners();
    job.worker = null;
  }
  if (status === "completed" && outcome.report && job.meta.onComplete) {
    job.meta.onComplete(outcome.report);
  }
  tryDequeue();
}

export function getScanJob(id: string): ScanJob | null {
  const job = jobs.get(id);
  return job ? toPublicJob(job) : null;
}

/** Ownership check for the routes layer — null means "anyone with the id." */
export function getScanJobOwner(id: string): string | null {
  return jobs.get(id)?.meta.ownerUserId ?? null;
}

export function cancelScanJob(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  if (job.status === "completed" || job.status === "failed" || job.status === "cancelled") return false;

  if (job.status === "queued") {
    const idx = queue.indexOf(id);
    if (idx >= 0) queue.splice(idx, 1);
    finishJob(job, "cancelled", {});
    return true;
  }

  // Running: terminate the worker outright. This is real cancellation, not
  // a client giving up on waiting — the child process actually stops.
  job.worker?.terminate();
  finishJob(job, "cancelled", {});
  return true;
}

function toPublicJob(job: InternalJob): ScanJob {
  return {
    id: job.id,
    status: job.status,
    source: job.input.mode,
    steps: job.steps.map((s) => ({ ...s })),
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    report: job.report,
    error: job.error,
    queuePosition: job.status === "queued" ? queue.indexOf(job.id) : null,
  };
}

// Bounded cleanup so long-lived server processes don't accumulate finished
// jobs forever. Matches the .unref() pattern already used elsewhere in this
// codebase for background intervals — never keeps the process alive on its
// own.
const JOB_RETENTION_MS = 60 * 60 * 1000; // 1 hour past completion
const sweepInterval = setInterval(() => {
  const cutoff = Date.now() - JOB_RETENTION_MS;
  for (const [id, job] of jobs) {
    if (job.finishedAt && new Date(job.finishedAt).getTime() < cutoff) {
      jobs.delete(id);
    }
  }
}, 10 * 60 * 1000);
sweepInterval.unref();

/** Test-only: reset all in-memory state between test files/runs. */
export function _resetScanJobsForTests(): void {
  for (const job of jobs.values()) job.worker?.terminate();
  jobs.clear();
  queue.length = 0;
  runningCount = 0;
}
