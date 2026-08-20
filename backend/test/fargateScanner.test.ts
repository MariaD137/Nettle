import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import path from "path";
import os from "os";
import {
  getFargateScannerConfig,
  launchFargateScan,
  stopFargateScanTask,
  MissingFargateConfigError,
  _resetFargateScannerForTests,
  type FargateScanInput,
  type FargateDeps,
} from "../src/jobs/fargateScanner";
import { resolvePendingScan, rejectPendingScan, _resetPendingScansForTests } from "../src/jobs/pendingScanRegistry";
import type { ScanReport } from "../src/scanner/types";

const REQUIRED_ENV = {
  NETTLE_SCANNER_CLUSTER_ARN: "arn:aws:ecs:us-east-1:123456789012:cluster/nettle-scanner",
  NETTLE_SCANNER_TASK_DEFINITION_ARN: "arn:aws:ecs:us-east-1:123456789012:task-definition/nettle-scanner:1",
  NETTLE_SCANNER_SUBNET_IDS: "subnet-aaa,subnet-bbb",
  NETTLE_SCANNER_SECURITY_GROUP_ID: "sg-0123456789abcdef0",
  NETTLE_SCAN_INPUT_BUCKET: "nettle-scan-input-test",
  NETTLE_SCANNER_CALLBACK_BASE_URL: "https://example.awsapprunner.com",
};

// Awaits fn() (not just calls it) before restoring — a `try { return fn(); }
// finally { restore }` with an async fn is a real bug: `finally` fires the
// instant fn() hits its own first `await` and returns a pending promise,
// not when that promise settles, which was restoring (deleting) these env
// vars while a test's own later `await`-resumed code still needed them.
async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => T | Promise<T>): Promise<T> {
  const original: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) original[key] = process.env[key];
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

// A minimal stand-in for the AWS SDK v3 clients — records every command
// sent and lets the test script canned responses, so nothing in this file
// ever makes a real network call to AWS. Matches the FargateDeps seam
// fargateScanner.ts was built with specifically for this.
function makeStubClient(handler: (commandName: string, input: unknown) => unknown) {
  const calls: { commandName: string; input: unknown }[] = [];
  const client = {
    send: async (command: { constructor: { name: string }; input: unknown }) => {
      const commandName = command.constructor.name;
      calls.push({ commandName, input: command.input });
      return handler(commandName, command.input);
    },
  };
  return { client, calls };
}

const validReport = { findings: [], passed: [], summary: { total: 0 } } as unknown as ScanReport;

// launchFargateScan does real async work (an awaited S3 upload, then an
// awaited RunTaskCommand) before it registers anything a test can observe
// — calling it without awaiting returns immediately, well before any of
// that has happened. This polls microtask ticks until a condition holds,
// so tests can wait for "the RunTask call has actually been made" instead
// of racing it.
async function waitUntil(condition: () => boolean, tries = 100): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (condition()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("waitUntil: condition never became true");
}

test.beforeEach(() => {
  _resetFargateScannerForTests();
  _resetPendingScansForTests();
});

test("getFargateScannerConfig throws MissingFargateConfigError when a required env var is absent", async () => {
  await withEnv({ ...REQUIRED_ENV, NETTLE_SCANNER_CLUSTER_ARN: undefined }, () => {
    assert.throws(() => getFargateScannerConfig(), MissingFargateConfigError);
  });
});

test("getFargateScannerConfig reads all required fields and defaults the task timeout", async () => {
  await withEnv(REQUIRED_ENV, () => {
    const config = getFargateScannerConfig();
    assert.equal(config.clusterArn, REQUIRED_ENV.NETTLE_SCANNER_CLUSTER_ARN);
    assert.deepEqual(config.subnetIds, ["subnet-aaa", "subnet-bbb"]);
    assert.equal(config.containerName, "scanner");
    assert.equal(config.taskTimeoutMs, 10 * 60 * 1000);
  });
});

test("launchFargateScan (repo mode) never touches S3 and resolves once the task calls back", async () => {
  await withEnv(REQUIRED_ENV, async () => {
    const { client: ecs, calls: ecsCalls } = makeStubClient((name, input) => {
      if (name === "RunTaskCommand") {
        return { tasks: [{ taskArn: "arn:aws:ecs:us-east-1:123456789012:task/nettle-scanner/abc" }], failures: [] };
      }
      throw new Error(`Unexpected ECS command: ${name}`);
    });
    const { client: s3, calls: s3Calls } = makeStubClient(() => {
      throw new Error("repo-mode scan should never call S3");
    });

    const input: FargateScanInput = { mode: "repo", repoUrl: "https://github.com/octocat/Hello-World", branch: "main", token: null };
    const resultPromise = launchFargateScan(input, "job-repo-1", { ecs, s3 } as FargateDeps);

    // Simulate the isolated task's own HTTP callback by extracting the
    // callback token this launch minted and handing it straight to
    // pendingScanRegistry, exactly as scanTaskCallback.routes.ts would.
    const runTaskCall = ecsCalls.find((c) => c.commandName === "RunTaskCommand")!;
    const env = (runTaskCall.input as any).overrides.containerOverrides[0].environment as { name: string; value: string }[];
    const jobId = env.find((e) => e.name === "NETTLE_SCAN_JOB_ID")!.value;
    const token = env.find((e) => e.name === "NETTLE_SCAN_CALLBACK_TOKEN")!.value;
    assert.equal(jobId, "job-repo-1");
    assert.equal(env.some((e) => e.name === "NETTLE_SCAN_REPO_URL"), true);
    assert.equal(env.some((e) => e.name === "NETTLE_SCAN_S3_KEY"), false);

    const claimed = resolvePendingScan(jobId, token, validReport);
    assert.equal(claimed, true);

    const report = await resultPromise;
    assert.equal(report, validReport);
    assert.equal(s3Calls.length, 0);
  });
});

test("launchFargateScan (upload mode) uploads the zip to S3, deletes the local file, and cleans up S3 once resolved", async () => {
  await withEnv(REQUIRED_ENV, async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fargate-upload-test-"));
    const zipPath = path.join(tmpDir, "codebase.zip");
    fs.writeFileSync(zipPath, "not a real zip, just bytes");

    const { client: ecs, calls: ecsCalls } = makeStubClient((name) => {
      if (name === "RunTaskCommand") {
        return { tasks: [{ taskArn: "arn:aws:ecs:us-east-1:123456789012:task/nettle-scanner/def" }], failures: [] };
      }
      throw new Error(`Unexpected ECS command: ${name}`);
    });
    const { client: s3, calls: s3Calls } = makeStubClient((name) => {
      if (name === "PutObjectCommand" || name === "DeleteObjectCommand") return {};
      throw new Error(`Unexpected S3 command: ${name}`);
    });

    try {
      const input: FargateScanInput = { mode: "upload", zipPath };
      const resultPromise = launchFargateScan(input, "job-upload-1", { ecs, s3 } as FargateDeps);

      // The upload (and the local-file delete right after it) happens
      // before RunTask is ever called — wait for RunTask so the assertions
      // below aren't racing launchFargateScan's own internal awaits.
      await waitUntil(() => ecsCalls.some((c) => c.commandName === "RunTaskCommand"));

      // The local upload should be gone well before the task has reported
      // back — fargateScanner.ts deletes it right after the S3 upload
      // succeeds, not in a caller-side finally.
      assert.equal(fs.existsSync(zipPath), false);

      const putCall = s3Calls.find((c) => c.commandName === "PutObjectCommand")!;
      assert.equal((putCall.input as any).Bucket, REQUIRED_ENV.NETTLE_SCAN_INPUT_BUCKET);
      assert.equal((putCall.input as any).Key, "uploads/job-upload-1.zip");

      const runTaskCall = ecsCalls.find((c) => c.commandName === "RunTaskCommand")!;
      const env = (runTaskCall.input as any).overrides.containerOverrides[0].environment as { name: string; value: string }[];
      assert.equal(env.find((e) => e.name === "NETTLE_SCAN_S3_KEY")!.value, "uploads/job-upload-1.zip");
      const token = env.find((e) => e.name === "NETTLE_SCAN_CALLBACK_TOKEN")!.value;

      resolvePendingScan("job-upload-1", token, validReport);
      const report = await resultPromise;
      assert.equal(report, validReport);

      const deleteCall = s3Calls.find((c) => c.commandName === "DeleteObjectCommand");
      assert.ok(deleteCall, "the S3 input object should be deleted once the task has reported back");
      assert.equal((deleteCall!.input as any).Key, "uploads/job-upload-1.zip");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

test("launchFargateScan rejects immediately (not waiting out the full timeout) when RunTask reports a failure, and cleans up S3", async () => {
  await withEnv(REQUIRED_ENV, async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fargate-launchfail-test-"));
    const zipPath = path.join(tmpDir, "codebase.zip");
    fs.writeFileSync(zipPath, "bytes");

    const { client: ecs } = makeStubClient((name) => {
      if (name === "RunTaskCommand") {
        return { tasks: [], failures: [{ arn: "?", reason: "RESOURCE:MEMORY" }] };
      }
      throw new Error(`Unexpected ECS command: ${name}`);
    });
    const { client: s3, calls: s3Calls } = makeStubClient((name) => {
      if (name === "PutObjectCommand" || name === "DeleteObjectCommand") return {};
      throw new Error(`Unexpected S3 command: ${name}`);
    });

    try {
      const input: FargateScanInput = { mode: "upload", zipPath };
      await assert.rejects(
        launchFargateScan(input, "job-launchfail-1", { ecs, s3 } as FargateDeps),
        /ECS RunTask failed/
      );
      const deleteCalls = s3Calls.filter((c) => c.commandName === "DeleteObjectCommand");
      assert.equal(deleteCalls.length, 1, "the uploaded input object should be cleaned up after a launch failure");
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

test("launchFargateScan rejects when the task itself later reports an error via the callback path", async () => {
  await withEnv(REQUIRED_ENV, async () => {
    const { client: ecs, calls: ecsCalls } = makeStubClient((name) => {
      if (name === "RunTaskCommand") {
        return { tasks: [{ taskArn: "arn:aws:ecs:us-east-1:123456789012:task/nettle-scanner/ghi" }], failures: [] };
      }
      throw new Error(`Unexpected ECS command: ${name}`);
    });
    const { client: s3 } = makeStubClient(() => {
      throw new Error("repo-mode scan should never call S3");
    });

    const input: FargateScanInput = { mode: "repo", repoUrl: "https://github.com/octocat/Hello-World", branch: "main", token: null };
    const resultPromise = launchFargateScan(input, "job-taskerror-1", { ecs, s3 } as FargateDeps);

    const runTaskCall = ecsCalls.find((c) => c.commandName === "RunTaskCommand")!;
    const env = (runTaskCall.input as any).overrides.containerOverrides[0].environment as { name: string; value: string }[];
    const token = env.find((e) => e.name === "NETTLE_SCAN_CALLBACK_TOKEN")!.value;

    rejectPendingScan("job-taskerror-1", token, "semgrep crashed on a malformed file");
    await assert.rejects(resultPromise, /semgrep crashed on a malformed file/);
  });
});

test("stopFargateScanTask calls StopTaskCommand for a launched task, and is a no-op for an unknown job", async () => {
  await withEnv(REQUIRED_ENV, async () => {
    const { client: ecs, calls: ecsCalls } = makeStubClient((name) => {
      if (name === "RunTaskCommand") {
        return { tasks: [{ taskArn: "arn:aws:ecs:us-east-1:123456789012:task/nettle-scanner/jkl" }], failures: [] };
      }
      if (name === "StopTaskCommand") return {};
      throw new Error(`Unexpected ECS command: ${name}`);
    });
    const { client: s3 } = makeStubClient(() => {
      throw new Error("repo-mode scan should never call S3");
    });

    const input: FargateScanInput = { mode: "repo", repoUrl: "https://github.com/octocat/Hello-World", branch: "main", token: null };
    const resultPromise = launchFargateScan(input, "job-stop-1", { ecs, s3 } as FargateDeps);
    // Don't await — cancel while it's still "running." But the task's ARN
    // isn't recorded until the awaited RunTaskCommand actually resolves
    // inside launchFargateScan, so wait for that first — otherwise
    // stopFargateScanTask would race it and see no task to stop yet.
    await waitUntil(() => ecsCalls.some((c) => c.commandName === "RunTaskCommand"));

    await stopFargateScanTask("job-stop-1", { ecs, s3 } as FargateDeps);
    const stopCall = ecsCalls.find((c) => c.commandName === "StopTaskCommand");
    assert.ok(stopCall, "StopTaskCommand should have been sent");
    assert.equal((stopCall!.input as any).task, "arn:aws:ecs:us-east-1:123456789012:task/nettle-scanner/jkl");

    // A no-op for a job that was never launched — must not throw.
    await assert.doesNotReject(stopFargateScanTask("no-such-job", { ecs, s3 } as FargateDeps));

    // Clean up: resolve the still-pending promise so the test process
    // doesn't leave a dangling unhandled rejection warning.
    const runTaskCall = ecsCalls.find((c) => c.commandName === "RunTaskCommand")!;
    const env = (runTaskCall.input as any).overrides.containerOverrides[0].environment as { name: string; value: string }[];
    const token = env.find((e) => e.name === "NETTLE_SCAN_CALLBACK_TOKEN")!.value;
    resolvePendingScan("job-stop-1", token, validReport);
    await resultPromise;
  });
});
