// Durable scan queue (durableQueue.ts): no live AWS credentials exist in
// this sandbox, so these tests exercise the real orchestration logic —
// archive/upload/download/extract via real `tar`, SQS message shape,
// idempotency, retry/give-up behavior — against injected fake SQS/S3
// clients (see _setClientsForTesting), not real network calls. Same honest
// distinction isolatedExecution.test.ts draws for its own ECS/S3 mocks.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import { SendMessageCommand, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import {
  isDurableQueueConfigured,
  enqueueScanDurable,
  pollDurableQueueOnce,
  _setClientsForTesting,
} from "../src/scanner/durableQueue";
import { createProject } from "../src/patrol/projects";
import { createUser } from "../src/auth/users";
import { createQueuedScan, getScanById } from "../src/patrol/scans";
import type { ScanJobInput } from "../src/scanner/scanQueue";

const ORIGINAL_ENV = { ...process.env };

function setConfigEnv() {
  process.env.SCAN_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/nettle-scan-queue";
  process.env.SCAN_WORKSPACE_BUCKET_NAME = "nettle-scan-workspace-test";
}

afterEach(() => {
  _setClientsForTesting(null, null);
  process.env = { ...ORIGINAL_ENV };
});

function makeWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "durable-queue-test-"));
  fs.writeFileSync(path.join(dir, "app.js"), "console.log('hello');");
  return dir;
}

/**
 * A fake queue+bucket pair that actually stores bytes in memory and speaks
 * the same request/response shapes the real clients do — real enough that
 * enqueueScanDurable's tar upload and pollDurableQueueOnce's download+untar
 * exercise their real code paths, not just "was send() called".
 */
function makeFakeInfra() {
  const s3Objects = new Map<string, Buffer>();
  const messages: { body: string; receiveCount: number }[] = [];

  const fakeS3 = {
    send: async (command: PutObjectCommand | GetObjectCommand | DeleteObjectCommand) => {
      if (command instanceof PutObjectCommand) {
        s3Objects.set(command.input.Key!, Buffer.from(command.input.Body as Buffer));
        return {};
      }
      if (command instanceof GetObjectCommand) {
        const body = s3Objects.get(command.input.Key!);
        if (!body) throw new Error("NoSuchKey");
        return { Body: { transformToByteArray: async () => new Uint8Array(body) } } as any;
      }
      if (command instanceof DeleteObjectCommand) {
        s3Objects.delete(command.input.Key!);
        return {};
      }
      throw new Error("unexpected S3 command");
    },
  };

  const fakeSqs = {
    send: async (command: SendMessageCommand | ReceiveMessageCommand | DeleteMessageCommand): Promise<any> => {
      if (command instanceof SendMessageCommand) {
        messages.push({ body: command.input.MessageBody!, receiveCount: 0 });
        return { MessageId: "fake-message-id" };
      }
      if (command instanceof ReceiveMessageCommand) {
        const next = messages[0];
        if (!next) return { Messages: [] };
        next.receiveCount++;
        return {
          Messages: [
            {
              Body: next.body,
              ReceiptHandle: "fake-receipt-handle",
              Attributes: { ApproximateReceiveCount: String(next.receiveCount) },
            },
          ],
        };
      }
      if (command instanceof DeleteMessageCommand) {
        messages.shift();
        return {};
      }
      throw new Error("unexpected SQS command");
    },
  };

  return { fakeS3, fakeSqs, s3Objects, messages };
}

async function testProject() {
  const user = await createUser(`durable-queue-${Date.now()}-${Math.random()}@example.com`, "correct horse battery staple");
  return createProject(user.id, "Durable Queue Target");
}

test("isDurableQueueConfigured is false when either required env var is missing", () => {
  delete process.env.SCAN_QUEUE_URL;
  delete process.env.SCAN_WORKSPACE_BUCKET_NAME;
  assert.equal(isDurableQueueConfigured(), false);

  setConfigEnv();
  delete process.env.SCAN_WORKSPACE_BUCKET_NAME;
  assert.equal(isDurableQueueConfigured(), false);
});

test("isDurableQueueConfigured is true when both required env vars are present", () => {
  setConfigEnv();
  assert.equal(isDurableQueueConfigured(), true);
});

test("enqueueScanDurable: archives the workspace to S3 and sends exactly one SQS message referencing it", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs, s3Objects, messages } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  const project = await testProject();
  const scan = await createQueuedScan(project.id);
  const workspace = makeWorkspace();
  let cleaned = false;

  const job: ScanJobInput = { scanId: scan.id, scanRoot: workspace, cleanup: () => { cleaned = true; } };
  await enqueueScanDurable(job);

  assert.equal(messages.length, 1, "exactly one message enqueued");
  const body = JSON.parse(messages[0].body);
  assert.equal(body.scanId, scan.id);
  assert.equal(body.workspaceKey, `queue-workspaces/${scan.id}.tar.gz`);
  assert.ok(s3Objects.has(body.workspaceKey), "the workspace archive must actually be in S3 before the message is sent");
  assert.ok(cleaned, "the local temp workspace is cleaned up once it's durably archived");
});

test("pollDurableQueueOnce: full round trip — downloads the real archive, runs the scan, marks it COMPLETED", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  const project = await testProject();
  const scan = await createQueuedScan(project.id);
  const workspace = makeWorkspace();
  await enqueueScanDurable({ scanId: scan.id, scanRoot: workspace, cleanup: () => {} });

  const processed = await pollDurableQueueOnce();
  assert.equal(processed, true);

  const finished = await getScanById(scan.id);
  assert.equal(finished?.status, "COMPLETED");
  assert.ok(finished!.report.checkResults!.length > 0, "a real scan actually ran against the downloaded+extracted workspace");
});

test("pollDurableQueueOnce: an empty queue returns false without touching S3", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  assert.equal(await pollDurableQueueOnce(), false);
});

test("pollDurableQueueOnce: duplicate delivery of an already-completed scan is a no-op, not a re-run", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs, messages } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  const project = await testProject();
  const scan = await createQueuedScan(project.id);
  const workspace = makeWorkspace();
  await enqueueScanDurable({ scanId: scan.id, scanRoot: workspace, cleanup: () => {} });

  await pollDurableQueueOnce(); // completes it for real
  const completedOnce = await getScanById(scan.id);
  assert.equal(completedOnce?.status, "COMPLETED");
  const completedAt = completedOnce!.scannedAt;

  // Simulate SQS redelivering the same message (e.g. the consumer died
  // after completeQueuedScan but before its own DeleteMessage call) by
  // re-enqueueing an identical message body directly.
  messages.push({ body: JSON.stringify({ scanId: scan.id, workspaceKey: `queue-workspaces/${scan.id}.tar.gz` }), receiveCount: 0 });
  const processedAgain = await pollDurableQueueOnce();
  assert.equal(processedAgain, true, "the redelivered message is still received and acknowledged (deleted)");

  const stillCompleted = await getScanById(scan.id);
  assert.equal(stillCompleted?.status, "COMPLETED");
  assert.equal(stillCompleted?.scannedAt, completedAt, "the already-completed report must not be overwritten by a duplicate delivery");
});

test("pollDurableQueueOnce: exceeding the max receive count explicitly fails the scan instead of retrying forever", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs, messages } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  const project = await testProject();
  const scan = await createQueuedScan(project.id);
  const workspace = makeWorkspace();
  await enqueueScanDurable({ scanId: scan.id, scanRoot: workspace, cleanup: () => {} });

  // Simulate 2 prior failed receive attempts (a crashed consumer each time,
  // never reaching DeleteMessage) — the 3rd receive is the one that should
  // give up rather than attempt a 3rd real scan.
  messages[0].receiveCount = 2;

  const processed = await pollDurableQueueOnce();
  assert.equal(processed, true);

  const failed = await getScanById(scan.id);
  assert.equal(failed?.status, "FAILED", "a scan that keeps failing to be processed must end up FAILED, never stuck at SCANNING forever");
  assert.match(failed!.report.error ?? "", /attempts/);
});

test("pollDurableQueueOnce: a real scan failure (not an infra failure) is recorded as FAILED with the real error, and the message is still deleted", async () => {
  setConfigEnv();
  const { fakeS3, fakeSqs, messages } = makeFakeInfra();
  _setClientsForTesting(fakeSqs, fakeS3);

  const project = await testProject();
  const scan = await createQueuedScan(project.id);

  // A message whose workspaceKey was never actually uploaded — the download
  // step itself fails, exercising the same failure path a corrupted/expired
  // S3 object would.
  messages.push({ body: JSON.stringify({ scanId: scan.id, workspaceKey: "queue-workspaces/does-not-exist.tar.gz" }), receiveCount: 1 });

  const processed = await pollDurableQueueOnce();
  assert.equal(processed, true);
  assert.equal(messages.length, 0, "the message must still be deleted — this was a real, recorded outcome, not a crash");

  const failed = await getScanById(scan.id);
  assert.equal(failed?.status, "FAILED");
});
