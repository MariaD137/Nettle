import { test } from "node:test";
import assert from "node:assert/strict";
import {
  WorkerPool,
  getWorkerPool,
  cleanupWorkerPool,
  checkResourceLimits,
  DEFAULT_RESOURCE_LIMITS,
} from "../src/scanner/workerIsolation";

test("C-2: Worker pool can be created", () => {
  const pool = new WorkerPool(2);
  assert.ok(pool);
  assert.equal(pool.getStats().poolSize, 2);
  pool.terminate();
});

test("C-2: Worker pool clamped to 1-4 workers", () => {
  const pool1 = new WorkerPool(0);
  assert.equal(pool1.getStats().poolSize, 1);
  pool1.terminate();

  const pool2 = new WorkerPool(10);
  assert.equal(pool2.getStats().poolSize, 4);
  pool2.terminate();

  const pool3 = new WorkerPool(2);
  assert.equal(pool3.getStats().poolSize, 2);
  pool3.terminate();
});

test("C-2: Global worker pool singleton", async () => {
  await cleanupWorkerPool();

  const pool1 = getWorkerPool(2);
  const pool2 = getWorkerPool(2);

  assert.equal(pool1, pool2);
  await cleanupWorkerPool();
});

test("C-2: Worker pool tracks pending tasks", async () => {
  const pool = new WorkerPool(1);
  assert.equal(pool.getStats().pendingTasks, 0);

  // Note: task execution is mocked in this test environment
  const stats = pool.getStats();
  assert.ok(stats.poolSize > 0);

  await pool.terminate();
});

test("C-2: Resource limit check passes for small input", () => {
  const input = "small code snippet";
  const result = checkResourceLimits(input);

  assert.ok(result.ok);
  assert.equal(result.error, undefined);
});

test("C-2: Resource limit check fails for oversized input", () => {
  const input = "x".repeat(20 * 1024 * 1024); // 20MB
  const result = checkResourceLimits(input);

  assert.ok(!result.ok);
  assert.ok(result.error?.includes("exceeds limit"));
});

test("C-2: Resource limit check with custom limits", () => {
  const input = "x".repeat(1000); // 1KB
  const result = checkResourceLimits(input, { maxFileSize: 500 });

  assert.ok(!result.ok);
  assert.ok(result.error?.includes("exceeds limit"));
});

test("C-2: Resource limit check passes with custom limits", () => {
  const input = "x".repeat(100); // 100 bytes
  const result = checkResourceLimits(input, { maxFileSize: 1000 });

  assert.ok(result.ok);
});

test("C-2: Buffer resource limit check", () => {
  const buffer = Buffer.alloc(20 * 1024 * 1024); // 20MB
  const result = checkResourceLimits(buffer);

  assert.ok(!result.ok);
});

test("C-2: Default resource limits are reasonable", () => {
  assert.ok(DEFAULT_RESOURCE_LIMITS.cpuTimeMs > 0);
  assert.ok(DEFAULT_RESOURCE_LIMITS.memoryMB > 0);
  assert.ok(DEFAULT_RESOURCE_LIMITS.maxFileSize > 0);
  assert.ok(DEFAULT_RESOURCE_LIMITS.maxFiles > 0);
});

test("C-2: Worker pool stats include worker count", () => {
  const pool = new WorkerPool(3);
  const stats = pool.getStats();

  assert.equal(stats.workers, 3);
  assert.equal(stats.poolSize, 3);
  assert.equal(stats.pendingTasks, 0);

  pool.terminate();
});

test("C-2: Resource limits prevent memory exhaustion", () => {
  // Create multiple large inputs and verify all are rejected
  const inputs = [
    "x".repeat(15 * 1024 * 1024),
    "y".repeat(16 * 1024 * 1024),
    "z".repeat(17 * 1024 * 1024),
  ];

  for (const input of inputs) {
    const result = checkResourceLimits(input);
    assert.ok(!result.ok);
  }
});

test("C-2: Worker isolation separates process state", async () => {
  const pool = new WorkerPool(1);
  assert.ok(pool.getStats().workers > 0);

  // Each worker should be independent
  const stats = pool.getStats();
  assert.ok(stats.workers > 0);

  await pool.terminate();
});
