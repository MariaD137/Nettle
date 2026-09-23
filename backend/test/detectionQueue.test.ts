// NETTLE_DB_PATH=:memory: is set by the `test` npm script — see the comment
// in patrol.test.ts for why an in-file assignment doesn't work.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createProject } from "../src/patrol/projects";
import { recordEvent } from "../src/patrol/events";
import { enqueueDetection, pendingDetectionJobs, flushDetectionQueue } from "../src/patrol/detectionQueue";
import { listAlerts } from "../src/patrol/alerts";
import { createUser } from "../src/auth/users";

let userId: string;
before(async () => {
  const user = await createUser("detection-queue-tests@example.com", "correct horse battery staple");
  userId = user.id;
});

test("enqueueDetection returns immediately and the job completes asynchronously", async () => {
  const project = await createProject(userId, "Async Target");
  const event = await recordEvent(project.id, { ip: "203.0.113.50", method: "GET", path: "/wp-login.php", statusCode: 404 });

  const before = pendingDetectionJobs();
  enqueueDetection(project.id, event);
  // The call itself must not have run detection synchronously — nothing
  // awaited it, so the job is still pending right after enqueueing.
  assert.equal(pendingDetectionJobs(), before + 1);

  await flushDetectionQueue();
  assert.equal(pendingDetectionJobs(), 0);

  const alerts = await listAlerts(project.id);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")), "expected the queued job to have actually run detection");
});

test("queued jobs converge on the same result as calling runDetection directly", async () => {
  const project = await createProject(userId, "Async Brute Force");
  for (let i = 0; i < 5; i++) {
    const event = await recordEvent(project.id, { ip: "203.0.113.51", method: "POST", path: "/login", statusCode: 401 });
    enqueueDetection(project.id, event);
  }
  await flushDetectionQueue();

  const alerts = await listAlerts(project.id);
  assert.ok(alerts.some((a) => a.rule === "brute-force"), "expected the async pipeline to fire the same brute-force alert as the synchronous one");
});

test("serial processing prevents the cooldown race a concurrent queue would allow", async () => {
  // Same shape as patrol.test.ts's synchronous cooldown test, but firing all
  // 10 events through the queue back-to-back with no await between them —
  // the scenario that would double-fire an alert if jobs ran concurrently
  // instead of one at a time, since two overlapping runDetection calls could
  // both pass the hasRecentAlert cooldown check before either alert write
  // lands.
  const project = await createProject(userId, "Async Sustained Attack");
  for (let i = 0; i < 10; i++) {
    const event = await recordEvent(project.id, { ip: "203.0.113.52", method: "POST", path: "/login", statusCode: 401 });
    enqueueDetection(project.id, event);
  }
  await flushDetectionQueue();

  const alerts = await listAlerts(project.id);
  assert.equal(
    alerts.filter((a) => a.rule === "brute-force").length,
    1,
    "expected exactly one brute-force alert despite 10 queued jobs racing to enqueue"
  );
});

test("a failing detection job doesn't break the queue for jobs after it", async () => {
  const project = await createProject(userId, "Resilient Target");
  const goodEvent = await recordEvent(project.id, { ip: "203.0.113.53", method: "GET", path: "/.env", statusCode: 404 });

  // detection.ts builds the alert's cooldown key as "suspicious-path-" +
  // event.ip — the `+` operator throws a genuine TypeError when asked to
  // coerce a Symbol to a string, giving a real (not simulated) exception
  // inside runDetection to prove it doesn't wedge the shared queue for
  // whatever's enqueued after it.
  const poisonedEvent = { ...goodEvent, ip: Symbol("unstringifiable") as unknown as string };
  enqueueDetection(project.id, poisonedEvent);
  enqueueDetection(project.id, goodEvent);
  await flushDetectionQueue();

  const alerts = await listAlerts(project.id);
  assert.ok(alerts.some((a) => a.rule.startsWith("suspicious-path")), "expected the job after the failing one to still have run");
});
