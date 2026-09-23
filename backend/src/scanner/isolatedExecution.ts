import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  type GetObjectCommandOutput,
  type PutObjectCommandOutput,
  type DeleteObjectCommandOutput,
} from "@aws-sdk/client-s3";
import {
  ECSClient,
  RunTaskCommand,
  DescribeTasksCommand,
  StopTaskCommand,
  type RunTaskCommandOutput,
  type DescribeTasksCommandOutput,
  type StopTaskCommandOutput,
} from "@aws-sdk/client-ecs";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import type { ScanReport } from "./types";

/**
 * True scan sandboxing: dispatches a scan to the isolated ECS Fargate task
 * scan-worker-stack.ts provisions, instead of running it in the API's own
 * process (scanQueue.ts's pre-existing in-process path — see that file's
 * own comment for exactly what it does and doesn't isolate, and why this
 * exists).
 *
 * isConfigured() is the single switch: all five SCAN_ECS_ and
 * SCAN_WORKSPACE_ env vars present (set by infra/lib/api-stack.ts only when
 * props.scanWorker is provided) means isolated execution is used; any
 * missing means it isn't, and scanQueue.ts falls back to the pre-existing
 * runScan() call. Local development, this sandbox, and every existing test
 * have none of these set, so they get the exact same behavior as before
 * this file existed — nothing here can break an environment that isn't
 * actually configured for it.
 */

interface IsolatedExecutionConfig {
  clusterArn: string;
  taskDefinitionArn: string;
  subnetIds: string[];
  securityGroupId: string;
  bucketName: string;
}

function loadConfig(): IsolatedExecutionConfig | null {
  const clusterArn = process.env.SCAN_ECS_CLUSTER_ARN;
  const taskDefinitionArn = process.env.SCAN_ECS_TASK_DEFINITION_ARN;
  const subnetIds = process.env.SCAN_ECS_SUBNET_IDS;
  const securityGroupId = process.env.SCAN_ECS_SECURITY_GROUP_ID;
  const bucketName = process.env.SCAN_WORKSPACE_BUCKET_NAME;
  if (!clusterArn || !taskDefinitionArn || !subnetIds || !securityGroupId || !bucketName) return null;
  return { clusterArn, taskDefinitionArn, subnetIds: subnetIds.split(","), securityGroupId, bucketName };
}

export function isIsolatedExecutionConfigured(): boolean {
  return loadConfig() !== null;
}

// Minimal interfaces, not the full SDK client types — same reasoning as
// notifications/email.ts's MinimalSesClient: this codebase has no HTTP-
// mocking library, so tests inject a fake object satisfying exactly the one
// method (and exactly the commands) this file actually calls, rather than
// fighting the real client classes' large internal surface.
interface MinimalS3Client {
  send(command: PutObjectCommand | GetObjectCommand | DeleteObjectCommand): Promise<PutObjectCommandOutput | GetObjectCommandOutput | DeleteObjectCommandOutput>;
}
interface MinimalEcsClient {
  send(command: RunTaskCommand | DescribeTasksCommand | StopTaskCommand): Promise<RunTaskCommandOutput | DescribeTasksCommandOutput | StopTaskCommandOutput>;
}

let s3Client: S3Client | null = null;
let ecsClient: ECSClient | null = null;
let s3Override: MinimalS3Client | null = null;
let ecsOverride: MinimalEcsClient | null = null;

function getS3(): MinimalS3Client {
  if (s3Override) return s3Override;
  if (!s3Client) s3Client = new S3Client({});
  return s3Client;
}

function getEcs(): MinimalEcsClient {
  if (ecsOverride) return ecsOverride;
  if (!ecsClient) ecsClient = new ECSClient({});
  return ecsClient;
}

/** Test-only seam — this codebase has no HTTP-mocking library (see notifications/email.ts's identical pattern), and a real ECS/S3 call needs live AWS credentials this sandbox never has. */
export function _setClientsForTesting(fakeS3: MinimalS3Client | null, fakeEcs: MinimalEcsClient | null): void {
  s3Override = fakeS3;
  ecsOverride = fakeEcs;
}

export class IsolatedScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IsolatedScanError";
  }
}

// Wall-clock budget for one isolated scan: task launch + Semgrep/OSV/control
// execution + results upload. Generous relative to Semgrep's own 30s
// internal timeout (semgrepControl.ts) because it also has to cover Fargate
// task provisioning time (image already cached on the cluster in steady
// state, but ENI attachment for a fresh task is itself commonly 10-30s) —
// configurable via env var since real-world scan sizes will tell us the
// right number faster than guessing one. Read per-call, not frozen at
// module load, so a test can override it (see isolatedExecution.test.ts's
// timeout case) without needing a fresh module instance.
function taskTimeoutMs(): number {
  return Number(process.env.SCAN_ISOLATED_TIMEOUT_MS) || 5 * 60 * 1000;
}
function pollIntervalMs(): number {
  return Number(process.env.SCAN_ISOLATED_POLL_INTERVAL_MS) || 3000;
}

/**
 * Runs one scan inside the isolated Fargate task and returns its real
 * report, or throws — never fabricates a result. Mirrors runScan()'s
 * signature/contract (scanQueue.ts calls whichever one applies), just with
 * the actual execution happening in a separate process/container/network
 * path rather than in-process.
 */
export async function runScanIsolated(scanId: string, scanRoot: string): Promise<ScanReport> {
  const config = loadConfig();
  if (!config) throw new IsolatedScanError("Isolated scan execution is not configured");

  const workspaceKey = `workspaces/${scanId}.tar.gz`;
  const resultsKey = `results/${scanId}.json`;
  const s3 = getS3();

  // tar, not a JS archiver dependency: the runtime image already has it
  // (Debian base), matching this codebase's existing preference for
  // shelling out to a real system tool (git, unzip, semgrep) over adding a
  // pure-JS reimplementation for something the OS already does correctly.
  const archivePath = path.join(os.tmpdir(), `${scanId}-workspace.tar.gz`);
  try {
    execFileSync("tar", ["-czf", archivePath, "-C", scanRoot, "."], { timeout: 60_000 });
    const archiveBody = fs.readFileSync(archivePath);
    await s3.send(new PutObjectCommand({ Bucket: config.bucketName, Key: workspaceKey, Body: archiveBody }));
  } finally {
    fs.rmSync(archivePath, { force: true });
  }

  let taskArn: string | undefined;
  try {
    const run = (await getEcs().send(
      new RunTaskCommand({
        cluster: config.clusterArn,
        taskDefinition: config.taskDefinitionArn,
        launchType: "FARGATE",
        networkConfiguration: {
          awsvpcConfiguration: {
            subnets: config.subnetIds,
            securityGroups: [config.securityGroupId],
            assignPublicIp: "DISABLED",
          },
        },
        overrides: {
          // "ScanWorker" — the exact container name scan-worker-stack.ts's
          // taskDefinition.addContainer("ScanWorker", ...) registers. Per-
          // scan identity/keys are supplied here, at RunTask time, never
          // baked into the task definition itself.
          containerOverrides: [
            {
              name: "ScanWorker",
              environment: [
                { name: "SCAN_ID", value: scanId },
                { name: "SCAN_WORKSPACE_BUCKET", value: config.bucketName },
                { name: "SCAN_WORKSPACE_KEY", value: workspaceKey },
                { name: "SCAN_RESULTS_KEY", value: resultsKey },
              ],
            },
          ],
        },
      })
    )) as RunTaskCommandOutput;

    if (run.failures?.length) {
      throw new IsolatedScanError(`ECS refused to launch the scan task: ${run.failures.map((f) => f.reason).join(", ")}`);
    }
    taskArn = run.tasks?.[0]?.taskArn;
    if (!taskArn) throw new IsolatedScanError("ECS RunTask returned no task");

    await waitForTaskCompletion(config.clusterArn, taskArn);

    // The task's own exit code is the primary success signal; the results
    // object existing is the secondary one. Both must hold — a task that
    // exited 0 but never wrote (a bug, a mid-upload crash) is still a
    // failure, not a silently empty "success".
    const results = await tryGetResults(config.bucketName, resultsKey);
    if (!results) {
      throw new IsolatedScanError("Scan task finished but produced no results — treating as a failed scan, not a clean one");
    }
    return results;
  } finally {
    if (taskArn) {
      // Best-effort: a task that's already stopped (the normal case) makes
      // this a no-op; one still running past our own timeout gets killed
      // here rather than left billing/running indefinitely.
      await getEcs()
        .send(new StopTaskCommand({ cluster: config.clusterArn, task: taskArn, reason: "scan orchestration finished or timed out" }))
        .catch(() => undefined);
    }
    await s3
      .send(new DeleteObjectCommand({ Bucket: config.bucketName, Key: workspaceKey }))
      .catch(() => undefined);
    await s3
      .send(new DeleteObjectCommand({ Bucket: config.bucketName, Key: resultsKey }))
      .catch(() => undefined);
  }
}

async function waitForTaskCompletion(clusterArn: string, taskArn: string): Promise<void> {
  const timeoutMs = taskTimeoutMs();
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const described = (await getEcs().send(new DescribeTasksCommand({ cluster: clusterArn, tasks: [taskArn] }))) as DescribeTasksCommandOutput;
    const task = described.tasks?.[0];
    if (task?.lastStatus === "STOPPED") {
      const exitCode = task.containers?.[0]?.exitCode;
      if (exitCode !== 0) {
        const reason = task.stoppedReason ?? task.containers?.[0]?.reason ?? "unknown";
        throw new IsolatedScanError(`Scan task failed (exit code ${exitCode ?? "unknown"}): ${reason}`);
      }
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs()));
  }
  throw new IsolatedScanError(`Scan task did not finish within ${timeoutMs}ms`);
}

async function tryGetResults(bucketName: string, resultsKey: string): Promise<ScanReport | null> {
  try {
    const object = (await getS3().send(new GetObjectCommand({ Bucket: bucketName, Key: resultsKey }))) as GetObjectCommandOutput;
    const body = await object.Body?.transformToString();
    if (!body) return null;
    return JSON.parse(body) as ScanReport;
  } catch {
    return null;
  }
}
