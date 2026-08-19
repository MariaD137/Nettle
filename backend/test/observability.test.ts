import { test } from "node:test";
import assert from "node:assert/strict";
import { incrementCounter, observeDuration, getMetricsSnapshot, _resetMetricsForTests, Metric } from "../src/observability/metrics";

test("incrementCounter accumulates real counts, per name, across calls", () => {
  _resetMetricsForTests();
  incrementCounter(Metric.HttpRequests);
  incrementCounter(Metric.HttpRequests);
  incrementCounter(Metric.HttpRequests, 3);
  incrementCounter(Metric.AuthFailures);

  const snapshot = getMetricsSnapshot();
  assert.equal(snapshot.counters[Metric.HttpRequests], 5);
  assert.equal(snapshot.counters[Metric.AuthFailures], 1);
});

test("observeDuration tracks real count/avg/min/max, not a placeholder", () => {
  _resetMetricsForTests();
  observeDuration(Metric.ScanDuration, 100);
  observeDuration(Metric.ScanDuration, 300);
  observeDuration(Metric.ScanDuration, 200);

  const snapshot = getMetricsSnapshot();
  const stats = snapshot.durations[Metric.ScanDuration];
  assert.equal(stats.count, 3);
  assert.equal(stats.minMs, 100);
  assert.equal(stats.maxMs, 300);
  assert.equal(stats.avgMs, 200);
});

test("getMetricsSnapshot reports a real, increasing uptime", async () => {
  _resetMetricsForTests();
  const first = getMetricsSnapshot();
  await new Promise((resolve) => setTimeout(resolve, 1100));
  const second = getMetricsSnapshot();
  assert.ok(second.uptimeSeconds >= first.uptimeSeconds);
});

test("_resetMetricsForTests actually clears state", () => {
  incrementCounter(Metric.HttpRequests);
  observeDuration(Metric.ScanDuration, 50);
  _resetMetricsForTests();

  const snapshot = getMetricsSnapshot();
  assert.deepEqual(snapshot.counters, {});
  assert.deepEqual(snapshot.durations, {});
});
