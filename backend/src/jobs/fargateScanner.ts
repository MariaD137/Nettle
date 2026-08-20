/**
 * Orchestrates a single scan by launching it as an isolated ECS Fargate
 * task, rather than running extraction/scanning in this process. See
 * scanner/ISOLATION.md for the full architecture. Only used when
 * NETTLE_SCANNER_BACKEND=fargate is set — see scanner/isolatedRunner.ts
 * for backend selection, and infra/lib/scanner-stack.ts /
 * infra/lib/api-stack.ts for what has to actually be deployed before this
 * config is present in a real environment.
 */
import { ECSClient, RunTaskCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { S3Client, PutObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import fs from "fs";
import type { ScanReport } from "../scanner/types";
import type { ScanWorkerInput } from "../scanner/scanWorker";
import { newCallbackToken, registerPendingScan } from "./pendingScanRegistry";

export type FargateScanInput = Extract<ScanWorkerInput, { mode: "upload" | "repo" }>;

export class MissingFargateConfigError extends Error {
  constructor(missing: string) {
    super(
      `NETTLE_SCANNER_BACKEND=fargate requires ${missing} to be set — see infra/lib/scanner-stack.ts's ` +
        "outputs and api-stack.ts's REQUIRES AWS CONFIGURATION notes for how to obtain and wire it in."
    );
  }
}

export interface FargateScannerConfig {
  clusterArn: string;
  taskDefinitionArn: string;
  subnetIds: string[];
  securityGroupId: string;
  containerName: string;
  scanInputBucket: string;
  callbackBaseUrl: string;
  taskTimeoutMs: number;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new MissingFargateConfigError(name);
  return value;
}

export function getFargateScannerConfig(): FargateScannerConfig {
  return {
    clusterArn: requiredEnv("NETTLE_SCANNER_CLUSTER_ARN"),
    taskDefinitionArn: requiredEnv("NETTLE_SCANNER_TASK_DEFINITION_ARN"),
    subnetIds: requiredEnv("NETTLE_SCANNER_SUBNET_IDS").split(",").map((s) => s.trim()).filter(Boolean),
    securityGroupId: requiredEnv("NETTLE_SCANNER_SECURITY_GROUP_ID"),
    containerName: process.env.NETTLE_SCANNER_CONTAINER_NAME || "scanner",
    scanInputBucket: requiredEnv("NETTLE_SCAN_INPUT_BUCKET"),
    callbackBaseUrl: requiredEnv("NETTLE_SCANNER_CALLBACK_BASE_URL"),
    taskTimeoutMs: parseInt(process.env.NETTLE_SCANNER_TASK_TIMEOUT_MS || "", 10) || 10 * 60 * 1000,
  };
}

// Test/DI seams — real AWS clients by default, swappable in tests so no
// test call ever reaches a real AWS endpoint. Matches the injectable-
// fetcher pattern already used elsewhere in this codebase (urlSecurity.ts,
// observability/opsAlert.ts).
export interface FargateDeps {
  ecs?: Pick<ECSClient, "send">;
  s3?: Pick<S3Client, "send">;
}

let defaultEcsClient: ECSClient | null = null;
let defaultS3Client: S3Client | null = null;
function ecs(deps?: FargateDeps): Pick<ECSClient, "send"> {
  if (deps?.ecs) return deps.ecs;
  if (!defaultEcsClient) defaultEcsClient = new ECSClient({});
  return defaultEcsClient;
}
function s3(deps?: FargateDeps): Pick<S3Client, "send"> {
  if (deps?.s3) return deps.s3;
  if (!defaultS3Client) defaultS3Client = new S3Client({});
  return defaultS3Client;
}

const taskArnByJobId = new Map<string, string>();

async function uploadZipToS3(config: FargateScannerConfig, jobId: string, zipPath: string, deps?: FargateDeps): Promise<string> {
  const key = `uploads/${jobId}.zip`;
  const body = fs.readFileSync(zipPath);
  await s3(deps).send(new PutObjectCommand({ Bucket: config.scanInputBucket, Key: key, Body: body }));
  // The local copy multer wrote to the API host's disk is no longer
  // needed once it's in S3 — the task reads from S3, never from this
  // host. Deleted here (not left for a caller's own finally block)
  // because the job-based route returns its 202 long before the scan
  // (and any caller-side cleanup) would run; force:true makes this safe
  // to call even if a caller's own cleanup already removed it.
  fs.rmSync(zipPath, { force: true });
  return key;
}

async function deleteFromS3(config: FargateScannerConfig, key: string, deps?: FargateDeps): Promise<void> {
  try {
    await s3(deps).send(new DeleteObjectCommand({ Bucket: config.scanInputBucket, Key: key }));
  } catch (err) {
    // Best-effort — the bucket's own lifecycle rule (infra/lib/scanner-stack.ts)
    // expires the object after 1 day regardless, so a failed delete here
    // isn't a durable leak, just a delayed one.
    console.error(`Failed to delete scan input object ${key}:`, err);
  }
}

/**
 * Launches one scan as an isolated Fargate task and returns a Promise that
 * resolves with the ScanReport once the task calls back (see
 * jobs/pendingScanRegistry.ts and routes/internal.routes.ts), or rejects
 * on task-launch failure, task failure, or timeout. Cleans up its S3
 * input object (upload mode) once the task has reported one way or the
 * other, regardless of outcome.
 */
export async function launchFargateScan(
  input: FargateScanInput,
  jobId: string,
  deps?: FargateDeps
): Promise<ScanReport> {
  const config = getFargateScannerConfig();
  const callbackToken = newCallbackToken();

  let s3Key: string | null = null;
  const environment: { name: string; value: string }[] = [
    { name: "NETTLE_SCAN_MODE", value: input.mode },
    { name: "NETTLE_SCAN_JOB_ID", value: jobId },
    { name: "NETTLE_SCAN_CALLBACK_URL", value: config.callbackBaseUrl },
    { name: "NETTLE_SCAN_CALLBACK_TOKEN", value: callbackToken },
  ];

  if (input.mode === "upload") {
    s3Key = await uploadZipToS3(config, jobId, input.zipPath, deps);
    environment.push({ name: "NETTLE_SCAN_S3_BUCKET", value: config.scanInputBucket }, { name: "NETTLE_SCAN_S3_KEY", value: s3Key });
  } else {
    environment.push(
      { name: "NETTLE_SCAN_REPO_URL", value: input.repoUrl },
      { name: "NETTLE_SCAN_REPO_BRANCH", value: input.branch || "" }
    );
    // Only included when present — an empty env var value is still a
    // present key, and taskEntrypoint.ts's readTaskEnv treats "" as
    // "no token" for repoToken specifically, so this is safe either way.
    if (input.token) environment.push({ name: "NETTLE_SCAN_REPO_TOKEN", value: input.token });
  }

  const resultPromise = registerPendingScan(jobId, callbackToken, config.taskTimeoutMs);

  try {
    const result = await ecs(deps).send(
      new RunTaskCommand({
        cluster: config.clusterArn,
        taskDefinition: config.taskDefinitionArn,
        launchType: "FARGATE",
        count: 1,
        networkConfiguration: {
          awsvpcConfiguration: {
            subnets: config.subnetIds,
            securityGroups: [config.securityGroupId],
            // The scanner task never needs to be reached from the
            // internet inbound — it only makes outbound calls (S3, git
            // hosts, its own callback) through the VPC's NAT gateway, the
            // same private-subnet path the API itself uses.
            assignPublicIp: "DISABLED",
          },
        },
        overrides: {
          containerOverrides: [{ name: config.containerName, environment }],
        },
      })
    );

    if (result.failures && result.failures.length > 0) {
      throw new Error(`ECS RunTask failed: ${result.failures.map((f) => `${f.arn ?? "?"}: ${f.reason ?? "unknown"}`).join("; ")}`);
    }
    const taskArn = result.tasks?.[0]?.taskArn;
    if (!taskArn) {
      throw new Error("ECS RunTask returned no task ARN");
    }
    taskArnByJobId.set(jobId, taskArn);
  } catch (err) {
    // Launch itself failed — nothing is running, reject immediately rather
    // than waiting out the full timeout for a callback that will never come.
    if (s3Key) await deleteFromS3(config, s3Key, deps);
    throw err;
  }

  try {
    const report = await resultPromise;
    return report;
  } finally {
    taskArnByJobId.delete(jobId);
    if (s3Key) await deleteFromS3(config, s3Key, deps);
  }
}

/**
 * Stops a still-running Fargate task for a cancelled job. A no-op (not an
 * error) if the job's task already finished and was removed from the map
 * — cancellation racing normal completion is expected, not exceptional.
 */
export async function stopFargateScanTask(jobId: string, deps?: FargateDeps): Promise<void> {
  const taskArn = taskArnByJobId.get(jobId);
  if (!taskArn) return;
  const config = getFargateScannerConfig();
  await ecs(deps).send(new StopTaskCommand({ cluster: config.clusterArn, task: taskArn, reason: "Scan cancelled by user" }));
  taskArnByJobId.delete(jobId);
}

/** Test-only: drops the default AWS SDK client singletons and the task-arn map. */
export function _resetFargateScannerForTests(): void {
  defaultEcsClient = null;
  defaultS3Client = null;
  taskArnByJobId.clear();
}
