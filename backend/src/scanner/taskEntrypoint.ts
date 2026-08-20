/**
 * Entry point for the isolated Fargate scanner task's container image
 * (see Dockerfile.scanner-task and infra/lib/scanner-stack.ts). This is a
 * standalone process — it is NOT part of the main Express app, is built
 * into its own, much smaller container image, and deliberately imports
 * nothing from db/, auth/, billing/, or integrations/: the task has no
 * database credentials, no Stripe/webhook/session secrets, and no way to
 * reach any Nettle-internal service other than the one callback URL it's
 * told to POST its result to.
 *
 * Reads its job entirely from environment variables (ECS RunTaskCommand
 * overrides — see jobs/fargateScanner.ts), runs the exact same extraction
 * + static-analysis pipeline scanWorker.ts uses for the worker_thread
 * backend, and reports back over one authenticated HTTP callback. See
 * ISOLATION.md for the full architecture and threat model this
 * implements.
 */
import fs from "fs";
import os from "os";
import path from "path";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { runScan, type ScanReport } from "./index";
import { safeExtractZip } from "./safeExtraction";
import { resolveScanRoot } from "./resolveScanRoot";
import { cloneRepo } from "./gitAuth";

export interface TaskEnv {
  mode: "upload" | "repo";
  jobId: string;
  callbackUrl: string;
  callbackToken: string;
  // upload mode
  s3Bucket?: string;
  s3Key?: string;
  // repo mode
  repoUrl?: string;
  repoBranch?: string;
  repoToken?: string | null;
}

export class MissingTaskEnvError extends Error {
  constructor(missing: string) {
    super(`Scanner task is missing required environment variable: ${missing}`);
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new MissingTaskEnvError(name);
  return value;
}

/** Parses and validates the task's environment. Exported so tests can construct one directly without setting real env vars. */
export function readTaskEnv(env: NodeJS.ProcessEnv = process.env): TaskEnv {
  const mode = env.NETTLE_SCAN_MODE;
  if (mode !== "upload" && mode !== "repo") {
    throw new MissingTaskEnvError("NETTLE_SCAN_MODE (must be 'upload' or 'repo')");
  }
  const base: TaskEnv = {
    mode,
    jobId: env.NETTLE_SCAN_JOB_ID || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_JOB_ID"); })(),
    callbackUrl: env.NETTLE_SCAN_CALLBACK_URL || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_CALLBACK_URL"); })(),
    callbackToken: env.NETTLE_SCAN_CALLBACK_TOKEN || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_CALLBACK_TOKEN"); })(),
  };
  if (mode === "upload") {
    base.s3Bucket = env.NETTLE_SCAN_S3_BUCKET || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_S3_BUCKET"); })();
    base.s3Key = env.NETTLE_SCAN_S3_KEY || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_S3_KEY"); })();
  } else {
    base.repoUrl = env.NETTLE_SCAN_REPO_URL || (() => { throw new MissingTaskEnvError("NETTLE_SCAN_REPO_URL"); })();
    base.repoBranch = env.NETTLE_SCAN_REPO_BRANCH || "";
    base.repoToken = env.NETTLE_SCAN_REPO_TOKEN || null;
  }
  return base;
}

async function downloadFromS3(bucket: string, key: string, destPath: string): Promise<void> {
  const client = new S3Client({});
  const result = await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  const body = result.Body;
  if (!body) throw new Error("S3 object has no body");
  const chunks: Buffer[] = [];
  // @ts-expect-error - Body is a Node Readable stream in the Node SDK runtime
  for await (const chunk of body) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  fs.writeFileSync(destPath, Buffer.concat(chunks));
}

async function postCallback(env: TaskEnv, path: "result" | "error", body: Record<string, unknown>): Promise<void> {
  const url = `${env.callbackUrl.replace(/\/$/, "")}/api/internal/scan-tasks/${env.jobId}/${path}`;
  try {
    await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Nettle-Scan-Callback-Token": env.callbackToken,
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    // Nothing left to do — the API's own timeout (see fargateScanner.ts)
    // is what catches an unreachable callback. Logging is all a task this
    // close to exiting can usefully do.
    console.error("Failed to deliver scan result callback:", err);
  }
}

/**
 * Runs one scan job end to end: obtain input, extract/clone, scan, report
 * back, clean up. Exported (rather than only called from main()) so tests
 * can exercise the full flow against a stubbed S3 client / callback
 * fetch without spawning a real process.
 */
export async function runTaskJob(env: TaskEnv): Promise<void> {
  if (env.mode === "upload") {
    const zipPath = path.join(os.tmpdir(), `nettle-task-${env.jobId}.zip`);
    const extractDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-task-upload-"));
    try {
      await downloadFromS3(env.s3Bucket!, env.s3Key!, zipPath);
      safeExtractZip(zipPath, extractDir);
      const scanRoot = resolveScanRoot(extractDir);
      const report: ScanReport = runScan(scanRoot, "SOURCE");
      await postCallback(env, "result", { report });
    } catch (err) {
      await postCallback(env, "error", { message: (err as Error).message || String(err) });
    } finally {
      fs.rmSync(zipPath, { force: true });
      fs.rmSync(extractDir, { recursive: true, force: true });
    }
  } else {
    const cloneDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-task-repo-"));
    try {
      cloneRepo(env.repoUrl!, env.repoBranch || "", cloneDir, env.repoToken);
      const report: ScanReport = runScan(cloneDir, "GITHUB");
      await postCallback(env, "result", { report });
    } catch (err) {
      await postCallback(env, "error", { message: (err as Error).message || String(err) });
    } finally {
      fs.rmSync(cloneDir, { recursive: true, force: true });
    }
  }
}

// A container-internal watchdog in addition to Fargate's own task-level
// stopTimeout (infra/lib/scanner-stack.ts) — defense in depth so a hang
// anywhere in this process still produces a failure callback instead of
// silently running until the platform kills it.
const TASK_WATCHDOG_MS = 9 * 60 * 1000; // under the 10-minute Fargate stopTimeout

async function main(): Promise<void> {
  const env = readTaskEnv();

  const watchdog = setTimeout(() => {
    postCallback(env, "error", { message: `Scan task exceeded its internal ${TASK_WATCHDOG_MS}ms watchdog` }).finally(
      () => process.exit(1)
    );
  }, TASK_WATCHDOG_MS);
  watchdog.unref();

  try {
    await runTaskJob(env);
  } finally {
    clearTimeout(watchdog);
  }
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("Scanner task failed unexpectedly:", err);
      process.exit(1);
    });
}
