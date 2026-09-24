// True scan sandboxing (isolatedExecution.ts + scan-worker-stack.ts): no
// live AWS credentials exist in this sandbox, so these tests exercise the
// real orchestration logic — command shapes, polling, failure/timeout
// handling, and the fact that two scans never share a workspace/results
// key — against injected fake S3/ECS clients (see _setClientsForTesting),
// not real network calls. That's real coverage of "does this codebase
// dispatch and interpret ECS/S3 correctly", not "was a task actually run in
// AWS" — the same honest distinction emailDelivery.test.ts draws for SES.
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { RunTaskCommand, DescribeTasksCommand, StopTaskCommand } from "@aws-sdk/client-ecs";
import { isIsolatedExecutionConfigured, runScanIsolated, IsolatedScanError, _setClientsForTesting } from "../src/scanner/isolatedExecution";
import fs from "fs";
import os from "os";
import path from "path";

const ORIGINAL_ENV = { ...process.env };

function setConfigEnv() {
  process.env.SCAN_ECS_CLUSTER_ARN = "arn:aws:ecs:us-east-1:123456789012:cluster/nettle-scan-worker";
  process.env.SCAN_ECS_TASK_DEFINITION_ARN = "arn:aws:ecs:us-east-1:123456789012:task-definition/nettle-scan-worker:1";
  process.env.SCAN_ECS_SUBNET_IDS = "subnet-aaa,subnet-bbb";
  process.env.SCAN_ECS_SECURITY_GROUP_ID = "sg-ccc";
  process.env.SCAN_WORKSPACE_BUCKET_NAME = "nettle-scan-workspace-test";
}

afterEach(() => {
  _setClientsForTesting(null, null);
  process.env = { ...ORIGINAL_ENV };
});

function makeWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "isolated-exec-test-"));
  fs.writeFileSync(path.join(dir, "app.js"), "console.log('hello');");
  return dir;
}

test("isIsolatedExecutionConfigured is false when any required env var is missing", () => {
  delete process.env.SCAN_ECS_CLUSTER_ARN;
  assert.equal(isIsolatedExecutionConfigured(), false);

  setConfigEnv();
  delete process.env.SCAN_WORKSPACE_BUCKET_NAME;
  assert.equal(isIsolatedExecutionConfigured(), false);
});

test("isIsolatedExecutionConfigured is true when every required env var is present", () => {
  setConfigEnv();
  assert.equal(isIsolatedExecutionConfigured(), true);
});

test("runScanIsolated: happy path — uploads the workspace, runs the task, downloads real results", async () => {
  setConfigEnv();
  const workspace = makeWorkspace();

  const fakeReport = { scannedAt: new Date().toISOString(), target: "app", score: 87, findings: [], passed: [], summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 } };

  let putCalls: PutObjectCommand[] = [];
  let deleteCalls: DeleteObjectCommand[] = [];
  let runTaskCall: RunTaskCommand | null = null;
  let describeCallCount = 0;

  _setClientsForTesting(
    {
      send: async (command: any) => {
        if (command instanceof PutObjectCommand) {
          putCalls.push(command);
          return {} as any;
        }
        if (command instanceof GetObjectCommand) {
          return { Body: { transformToString: async () => JSON.stringify(fakeReport) } } as any;
        }
        if (command instanceof DeleteObjectCommand) {
          deleteCalls.push(command);
          return {} as any;
        }
        throw new Error("unexpected S3 command");
      },
    },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) {
          runTaskCall = command;
          return { tasks: [{ taskArn: "arn:aws:ecs:us-east-1:123456789012:task/nettle-scan-worker/abc123" }], failures: [] } as any;
        }
        if (command instanceof DescribeTasksCommand) {
          describeCallCount++;
          return { tasks: [{ lastStatus: "STOPPED", containers: [{ exitCode: 0 }] }] } as any;
        }
        if (command instanceof StopTaskCommand) {
          return {} as any;
        }
        throw new Error("unexpected ECS command");
      },
    }
  );

  const report = await runScanIsolated("scan-happy-1", workspace);
  assert.equal(report.score, 87);

  // The workspace was actually uploaded, not skipped.
  assert.equal(putCalls.length, 1);
  assert.equal((putCalls[0] as any).input.Key, "workspaces/scan-happy-1.tar.gz");
  assert.equal((putCalls[0] as any).input.Bucket, "nettle-scan-workspace-test");

  // RunTask carried the real cluster/task-definition/network config, plus
  // the per-scan identity via container overrides — never baked into a
  // shared task definition.
  assert.ok(runTaskCall);
  const runInput = (runTaskCall as any).input;
  assert.equal(runInput.cluster, process.env.SCAN_ECS_CLUSTER_ARN);
  assert.equal(runInput.taskDefinition, process.env.SCAN_ECS_TASK_DEFINITION_ARN);
  assert.equal(runInput.launchType, "FARGATE");
  assert.deepEqual(runInput.networkConfiguration.awsvpcConfiguration.subnets, ["subnet-aaa", "subnet-bbb"]);
  assert.equal(runInput.networkConfiguration.awsvpcConfiguration.assignPublicIp, "DISABLED");
  const env = runInput.overrides.containerOverrides[0].environment;
  assert.ok(env.some((e: any) => e.name === "SCAN_ID" && e.value === "scan-happy-1"));
  assert.ok(env.some((e: any) => e.name === "SCAN_WORKSPACE_KEY" && e.value === "workspaces/scan-happy-1.tar.gz"));
  assert.ok(env.some((e: any) => e.name === "SCAN_RESULTS_KEY" && e.value === "results/scan-happy-1.json"));

  assert.ok(describeCallCount >= 1, "must actually poll task status, not assume completion");

  // Cleanup: both the workspace and results objects get deleted afterward.
  assert.equal(deleteCalls.length, 2);
  const deletedKeys = deleteCalls.map((c) => (c as any).input.Key).sort();
  assert.deepEqual(deletedKeys, ["results/scan-happy-1.json", "workspaces/scan-happy-1.tar.gz"]);

  fs.rmSync(workspace, { recursive: true, force: true });
});

test("runScanIsolated: a real task failure (non-zero exit) throws, never a fabricated report, and still cleans up", async () => {
  setConfigEnv();
  const workspace = makeWorkspace();

  const deletedKeys: string[] = [];
  let stopTaskCalled = false;
  _setClientsForTesting(
    {
      send: async (command: any) => {
        if (command instanceof DeleteObjectCommand) deletedKeys.push(command.input.Key!);
        return {} as any;
      },
    },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) return { tasks: [{ taskArn: "arn:task/1" }], failures: [] } as any;
        if (command instanceof DescribeTasksCommand) {
          return { tasks: [{ lastStatus: "STOPPED", containers: [{ exitCode: 1, reason: "OutOfMemoryError: Container killed" }], stoppedReason: "OutOfMemoryError" }] } as any;
        }
        if (command instanceof StopTaskCommand) {
          stopTaskCalled = true;
          return {} as any;
        }
        return {} as any;
      },
    }
  );

  await assert.rejects(() => runScanIsolated("scan-fail-1", workspace), (err: unknown) => {
    assert.ok(err instanceof IsolatedScanError);
    assert.match((err as Error).message, /exit code 1/);
    return true;
  });

  // A failed scan must clean up exactly like a successful one — no leaked
  // workspace/results objects, no task left believing it should still run.
  assert.deepEqual(deletedKeys.sort(), ["results/scan-fail-1.json", "workspaces/scan-fail-1.tar.gz"]);
  assert.equal(stopTaskCalled, true);

  fs.rmSync(workspace, { recursive: true, force: true });
});

test("runScanIsolated: exit code 0 but no results object still fails — never a silent empty success", async () => {
  setConfigEnv();
  const workspace = makeWorkspace();

  _setClientsForTesting(
    {
      send: async (command: any) => {
        if (command instanceof GetObjectCommand) throw new Error("NoSuchKey");
        return {} as any;
      },
    },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) return { tasks: [{ taskArn: "arn:task/2" }], failures: [] } as any;
        if (command instanceof DescribeTasksCommand) return { tasks: [{ lastStatus: "STOPPED", containers: [{ exitCode: 0 }] }] } as any;
        return {} as any;
      },
    }
  );

  await assert.rejects(() => runScanIsolated("scan-noresults-1", workspace), /produced no results/);

  fs.rmSync(workspace, { recursive: true, force: true });
});

test("runScanIsolated: ECS refusing to launch the task (e.g. capacity failure) throws cleanly", async () => {
  setConfigEnv();
  const workspace = makeWorkspace();

  _setClientsForTesting(
    { send: async () => ({}) as any },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) {
          return { tasks: [], failures: [{ reason: "RESOURCE:FARGATE" }] } as any;
        }
        return {} as any;
      },
    }
  );

  await assert.rejects(() => runScanIsolated("scan-refused-1", workspace), /ECS refused to launch/);

  fs.rmSync(workspace, { recursive: true, force: true });
});

test("two concurrent scans never share a workspace or results key", async () => {
  setConfigEnv();
  const workspaceA = makeWorkspace();
  const workspaceB = makeWorkspace();

  const fakeReport = { scannedAt: new Date().toISOString(), target: "x", score: 100, findings: [], passed: [], summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, clear: 0 } };
  const putKeys: string[] = [];

  _setClientsForTesting(
    {
      send: async (command: any) => {
        if (command instanceof PutObjectCommand) putKeys.push(command.input.Key!);
        if (command instanceof GetObjectCommand) return { Body: { transformToString: async () => JSON.stringify(fakeReport) } } as any;
        return {} as any;
      },
    },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) return { tasks: [{ taskArn: `arn:task/${Math.random()}` }], failures: [] } as any;
        if (command instanceof DescribeTasksCommand) return { tasks: [{ lastStatus: "STOPPED", containers: [{ exitCode: 0 }] }] } as any;
        return {} as any;
      },
    }
  );

  await Promise.all([runScanIsolated("scan-concurrent-a", workspaceA), runScanIsolated("scan-concurrent-b", workspaceB)]);

  assert.equal(new Set(putKeys).size, 2, "each scan must get its own distinct workspace key");
  assert.ok(putKeys.includes("workspaces/scan-concurrent-a.tar.gz"));
  assert.ok(putKeys.includes("workspaces/scan-concurrent-b.tar.gz"));

  fs.rmSync(workspaceA, { recursive: true, force: true });
  fs.rmSync(workspaceB, { recursive: true, force: true });
});

test("a task that never reaches STOPPED is timed out and stopped, not left running forever", async () => {
  setConfigEnv();
  process.env.SCAN_ISOLATED_TIMEOUT_MS = "50"; // fast for the test — real default is 5 minutes
  process.env.SCAN_ISOLATED_POLL_INTERVAL_MS = "10"; // real default is 3000ms
  const workspace = makeWorkspace();

  let stopTaskCalled = false;
  _setClientsForTesting(
    { send: async () => ({}) as any },
    {
      send: async (command: any) => {
        if (command instanceof RunTaskCommand) return { tasks: [{ taskArn: "arn:task/stuck" }], failures: [] } as any;
        if (command instanceof DescribeTasksCommand) return { tasks: [{ lastStatus: "RUNNING", containers: [] }] } as any; // never STOPPED
        if (command instanceof StopTaskCommand) {
          stopTaskCalled = true;
          return {} as any;
        }
        return {} as any;
      },
    }
  );

  await assert.rejects(() => runScanIsolated("scan-timeout-1", workspace), /did not finish within/);
  assert.equal(stopTaskCalled, true, "a timed-out task must be explicitly stopped, not left running/billing indefinitely");

  fs.rmSync(workspace, { recursive: true, force: true });
});

test("runScanIsolated throws immediately, with no AWS calls, when not configured", async () => {
  delete process.env.SCAN_ECS_CLUSTER_ARN;
  const workspace = makeWorkspace();

  let calledAws = false;
  _setClientsForTesting(
    { send: async () => { calledAws = true; return {} as any; } },
    { send: async () => { calledAws = true; return {} as any; } }
  );

  await assert.rejects(() => runScanIsolated("scan-unconfigured-1", workspace), /not configured/);
  assert.equal(calledAws, false);

  fs.rmSync(workspace, { recursive: true, force: true });
});
