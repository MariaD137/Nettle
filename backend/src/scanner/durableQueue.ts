import {
  SQSClient,
  SendMessageCommand,
  ReceiveMessageCommand,
  DeleteMessageCommand,
  type SendMessageCommandOutput,
  type ReceiveMessageCommandOutput,
  type DeleteMessageCommandOutput,
} from "@aws-sdk/client-sqs";
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, type GetObjectCommandOutput } from "@aws-sdk/client-s3";
import { execFileSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { runScan } from "./index";
import { completeQueuedScan, failQueuedScan, markScanStatus, getScanById } from "../patrol/scans";
import { isIsolatedExecutionConfigured, runScanIsolated } from "./isolatedExecution";
import type { ScanJobInput } from "./scanQueue";

/**
 * Durable replacement for scanQueue.ts's in-memory job list. That module's
 * own comment discloses the gap this closes: "If the process crashes or
 * restarts while a job is queued or mid-SCANNING, that job is lost... nothing
 * currently sweeps and fails stale in-flight rows." SQS is the fix — a
 * message isn't removed from the queue until the consumer explicitly deletes
 * it after finishing, so a process that dies mid-scan leaves the message to
 * become visible again (once its visibility timeout elapses) for whichever
 * process is polling next, including a freshly restarted one.
 *
 * What this does NOT change: scanner/isolatedExecution.ts's ECS Fargate
 * isolation boundary is untouched — this queue only makes *dispatch*
 * durable; once a message is picked up, execution still goes through the
 * exact same isIsolatedExecutionConfigured() ? runScanIsolated() : runScan()
 * branch scanQueue.ts's in-memory runJob() always used.
 *
 * Source handoff: the job's scanRoot is a local temp directory on whichever
 * API instance received the original HTTP request — meaningless to any
 * other process, and gone entirely once that process's disk is reclaimed.
 * So enqueueScanDurable() tars it and uploads it to S3 (the same
 * ScanWorkspaceBucket isolatedExecution.ts already uses, under a distinct
 * queue-workspaces/ prefix so the two never collide) *before* sending the
 * SQS message, and the message carries only the S3 key, never a local path.
 * Whichever process's poller picks the message up downloads and extracts a
 * fresh copy — correct whether that's the same instance, a different one,
 * or the same instance after a restart.
 *
 * Configuration mirrors isolatedExecution.ts's own pattern exactly: present
 * (SCAN_QUEUE_URL, plus the SCAN_WORKSPACE_BUCKET_NAME isolatedExecution.ts
 * already requires) means durable; absent means every test, local dev, and
 * this sandbox keep exactly scanQueue.ts's pre-existing in-memory behavior.
 */

interface DurableQueueConfig {
  queueUrl: string;
  bucketName: string;
}

function loadConfig(): DurableQueueConfig | null {
  const queueUrl = process.env.SCAN_QUEUE_URL;
  const bucketName = process.env.SCAN_WORKSPACE_BUCKET_NAME;
  if (!queueUrl || !bucketName) return null;
  return { queueUrl, bucketName };
}

export function isDurableQueueConfigured(): boolean {
  return loadConfig() !== null;
}

interface MinimalSqsClient {
  send(
    command: SendMessageCommand | ReceiveMessageCommand | DeleteMessageCommand
  ): Promise<SendMessageCommandOutput | ReceiveMessageCommandOutput | DeleteMessageCommandOutput>;
}
interface MinimalS3Client {
  send(command: PutObjectCommand | GetObjectCommand | DeleteObjectCommand): Promise<unknown>;
}

let sqsClient: SQSClient | null = null;
let s3Client: S3Client | null = null;
let sqsOverride: MinimalSqsClient | null = null;
let s3Override: MinimalS3Client | null = null;

function getSqs(): MinimalSqsClient {
  if (sqsOverride) return sqsOverride;
  if (!sqsClient) sqsClient = new SQSClient({});
  return sqsClient;
}
function getS3(): MinimalS3Client {
  if (s3Override) return s3Override;
  if (!s3Client) s3Client = new S3Client({});
  return s3Client;
}

/** Test-only seam, same pattern as isolatedExecution.ts's _setClientsForTesting. */
export function _setClientsForTesting(fakeSqs: MinimalSqsClient | null, fakeS3: MinimalS3Client | null): void {
  sqsOverride = fakeSqs;
  s3Override = fakeS3;
}

/**
 * A message is redelivered (ApproximateReceiveCount increments) each time a
 * consumer receives it without deleting it — a crash mid-processing, or a
 * process that hung past the visibility timeout. scan-worker-stack.ts's
 * queue sends it to the DLQ after 3 such receives. Explicitly failing the
 * scan record once the count reaches this threshold means a scan that ends
 * up in the DLQ still leaves a real, customer-visible FAILED result behind,
 * rather than a row stuck at SCANNING forever with no explanation — the
 * same "no scan can remain SCANNING forever without a recovery path"
 * requirement isolatedExecution.ts already meets for a hung Fargate task.
 */
const MAX_RECEIVES_BEFORE_GIVING_UP = 3;

interface DurableMessageBody {
  scanId: string;
  workspaceKey: string;
}

/**
 * Uploads the scan's already-extracted, already-validated source (safeExtractZip
 * or git clone already ran before this is called — same as isolatedExecution.ts)
 * to S3, then enqueues a durable SQS message referencing it. Returns once the
 * message is confirmed accepted by SQS — from that point on, the scan survives
 * this process disappearing.
 */
export async function enqueueScanDurable(job: ScanJobInput): Promise<void> {
  const config = loadConfig();
  if (!config) throw new Error("Durable scan queue is not configured");

  const workspaceKey = `queue-workspaces/${job.scanId}.tar.gz`;
  const archivePath = path.join(os.tmpdir(), `${job.scanId}-queue-workspace.tar.gz`);
  try {
    execFileSync("tar", ["-czf", archivePath, "-C", job.scanRoot, "."], { timeout: 60_000 });
    const archiveBody = fs.readFileSync(archivePath);
    await getS3().send(new PutObjectCommand({ Bucket: config.bucketName, Key: workspaceKey, Body: archiveBody }));
  } finally {
    fs.rmSync(archivePath, { force: true });
  }

  const body: DurableMessageBody = { scanId: job.scanId, workspaceKey };
  await getSqs().send(new SendMessageCommand({ QueueUrl: config.queueUrl, MessageBody: JSON.stringify(body) }));

  // The local extracted copy is now redundant with the S3 archive — safe to
  // clean it up immediately rather than waiting for a worker to process it,
  // since whichever process consumes the SQS message downloads its own copy.
  job.cleanup();
}

async function downloadAndExtractWorkspace(bucketName: string, workspaceKey: string): Promise<string> {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), "nettle-durable-scan-"));
  const archivePath = path.join(os.tmpdir(), `${path.basename(workspaceKey)}-download.tar.gz`);
  try {
    const object = (await getS3().send(new GetObjectCommand({ Bucket: bucketName, Key: workspaceKey }))) as GetObjectCommandOutput;
    const bytes = await object.Body?.transformToByteArray();
    if (!bytes) throw new Error("Workspace object has no body");
    fs.writeFileSync(archivePath, bytes);
    execFileSync("tar", ["-xzf", archivePath, "-C", workDir], { timeout: 60_000 });
    return workDir;
  } finally {
    fs.rmSync(archivePath, { force: true });
  }
}

/**
 * Receives and fully processes at most one message. Returns true if a
 * message was received (whether processing succeeded, failed, or was a
 * duplicate skipped as already-terminal), false if the queue was empty —
 * the caller (the poll loop, or a test) uses that to decide whether to
 * back off before polling again.
 */
export async function pollDurableQueueOnce(): Promise<boolean> {
  const config = loadConfig();
  if (!config) return false;

  const received = (await getSqs().send(
    new ReceiveMessageCommand({
      QueueUrl: config.queueUrl,
      MaxNumberOfMessages: 1,
      WaitTimeSeconds: 0,
      MessageSystemAttributeNames: ["ApproximateReceiveCount"],
    })
  )) as ReceiveMessageCommandOutput;

  const message = received.Messages?.[0];
  if (!message?.Body || !message.ReceiptHandle) return false;

  const { scanId, workspaceKey } = JSON.parse(message.Body) as DurableMessageBody;
  const receiveCount = Number(message.Attributes?.ApproximateReceiveCount ?? "1");

  const deleteMessage = () =>
    getSqs().send(new DeleteMessageCommand({ QueueUrl: config.queueUrl, ReceiptHandle: message.ReceiptHandle! }));

  // Idempotency / duplicate-delivery protection: SQS is at-least-once, so a
  // message already fully processed (completeQueuedScan/failQueuedScan
  // already ran) but redelivered — e.g. the process died after finishing
  // but before this function's own DeleteMessage call below — must be a
  // no-op, not a second scan run against a report that's already there.
  const existing = await getScanById(scanId);
  if (existing && existing.status !== "CREATED" && existing.status !== "SCANNING") {
    await deleteMessage().catch(() => undefined);
    return true;
  }

  if (receiveCount >= MAX_RECEIVES_BEFORE_GIVING_UP) {
    console.error(`[durable-queue] scan ${scanId} exceeded ${MAX_RECEIVES_BEFORE_GIVING_UP} receive attempts — giving up, not retrying further`);
    await failQueuedScan(scanId, `This scan could not be completed after ${MAX_RECEIVES_BEFORE_GIVING_UP} attempts and was abandoned.`);
    await getS3().send(new DeleteObjectCommand({ Bucket: config.bucketName, Key: workspaceKey })).catch(() => undefined);
    await deleteMessage().catch(() => undefined);
    return true;
  }

  await markScanStatus(scanId, "SCANNING");
  let workDir: string | null = null;
  try {
    workDir = await downloadAndExtractWorkspace(config.bucketName, workspaceKey);
    const report = isIsolatedExecutionConfigured() ? await runScanIsolated(scanId, workDir) : runScan(workDir);
    await completeQueuedScan(scanId, report);
  } catch (err) {
    const message2 = (err as Error).message;
    console.error(`[durable-queue] scan ${scanId} failed: ${message2}`);
    await failQueuedScan(scanId, message2);
  } finally {
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
    await getS3().send(new DeleteObjectCommand({ Bucket: config.bucketName, Key: workspaceKey })).catch(() => undefined);
  }

  // Reaching here means processing ran to a real, recorded terminal state
  // (completed or explicitly failed) — always delete on this path. A
  // message is only ever left for SQS's own redelivery when the process
  // dies before this line runs at all (a hard crash mid-processing).
  await deleteMessage().catch(() => undefined);
  return true;
}

let polling = false;

/** Background consumer loop — started once at process boot (index.ts) when the durable queue is configured. */
export function startDurableQueueConsumer(): void {
  if (!isDurableQueueConfigured() || polling) return;
  polling = true;
  void consumeLoop();
}

/** Test-only: stops the background loop started by startDurableQueueConsumer(). */
export function stopDurableQueueConsumer(): void {
  polling = false;
}

async function consumeLoop(): Promise<void> {
  while (polling) {
    let processed = false;
    try {
      processed = await pollDurableQueueOnce();
    } catch (err) {
      console.error(`[durable-queue] poll error: ${(err as Error).message}`);
    }
    if (!processed) await new Promise((resolve) => setTimeout(resolve, 3000));
  }
}
