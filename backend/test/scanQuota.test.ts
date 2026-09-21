import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser, setSubscriptionStatus, getUserById, deleteUser } from "../src/auth/users";
import { db } from "../src/db";
import {
  SCAN_QUOTAS,
  currentPeriod,
  recordScanUsage,
  countScanUsage,
  getQuotaState,
} from "../src/billing/scanQuota";

const PASSWORD = "correct horse battery staple";

async function subscriber(email: string, plan: "tier1" | "tier2" = "tier1") {
  const user = await createUser(email, PASSWORD);
  await setSubscriptionStatus(user.id, plan, "active");
  return user.id;
}

test("the period rolls forward a month at a time from the anchor", () => {
  const anchor = "2026-01-10T09:00:00.000Z";

  // Same month as the anchor.
  let p = currentPeriod(anchor, new Date("2026-01-20T00:00:00Z"));
  assert.equal(p.start.toISOString(), "2026-01-10T09:00:00.000Z");
  assert.equal(p.end.toISOString(), "2026-02-10T09:00:00.000Z");

  // Several months later — the period must be the one containing `now`,
  // not the original anchor month.
  p = currentPeriod(anchor, new Date("2026-04-11T00:00:00Z"));
  assert.equal(p.start.toISOString(), "2026-04-10T09:00:00.000Z");
  assert.equal(p.end.toISOString(), "2026-05-10T09:00:00.000Z");
});

test("an end-of-month anchor clamps instead of skipping a month", () => {
  // Anchored on the 31st: February has no 31st, so the period must land on
  // the 28th rather than rolling into March and skipping February entirely.
  const p = currentPeriod("2026-01-31T00:00:00.000Z", new Date("2026-02-15T00:00:00Z"));
  assert.equal(p.start.toISOString(), "2026-01-31T00:00:00.000Z");
  assert.equal(p.end.toISOString(), "2026-02-28T00:00:00.000Z");
});

test("the boundary belongs to the new period, not the old one", () => {
  const anchor = "2026-03-01T00:00:00.000Z";
  const atBoundary = currentPeriod(anchor, new Date("2026-04-01T00:00:00.000Z"));
  assert.equal(atBoundary.start.toISOString(), "2026-04-01T00:00:00.000Z");
});

test("subscribing stamps a billing anchor, and it never moves afterwards", async () => {
  const id = await subscriber("quota-anchor@example.com");
  const first = (await getUserById(id))!.billingAnchor;
  assert.ok(first, "an active subscription must have an anchor");

  // A later webhook (renewal, plan change) must not reset the anchor —
  // doing so would silently wipe the customer's usage mid-cycle.
  await setSubscriptionStatus(id, "tier2", "active");
  assert.equal((await getUserById(id))!.billingAnchor, first);
});

test("usage counts only the requested period", async () => {
  const id = await subscriber("quota-count@example.com");
  await recordScanUsage(id, null, "upload");
  await recordScanUsage(id, null, "repo");

  assert.equal(await countScanUsage(id, new Date("2000-01-01T00:00:00Z")), 2);
  // A window starting in the future contains nothing.
  assert.equal(await countScanUsage(id, new Date(Date.now() + 60_000)), 0);
});

test("one account's scans never count against another's allowance", async () => {
  const alice = await subscriber("quota-alice@example.com");
  const bob = await subscriber("quota-bob@example.com");

  for (let i = 0; i < 5; i++) await recordScanUsage(alice, null, "upload");

  assert.equal((await getQuotaState(alice))!.used, 5);
  assert.equal((await getQuotaState(bob))!.used, 0);
  assert.equal((await getQuotaState(bob))!.remaining, SCAN_QUOTAS.tier1);
});

test("quota state reports remaining and flips to exhausted at the limit", async () => {
  const id = await subscriber("quota-exhaust@example.com");
  const limit = SCAN_QUOTAS.tier1;

  let state = (await getQuotaState(id))!;
  assert.equal(state.limit, limit);
  assert.equal(state.remaining, limit);
  assert.equal(state.exhausted, false);

  for (let i = 0; i < limit - 1; i++) await recordScanUsage(id, null, "upload");
  state = (await getQuotaState(id))!;
  assert.equal(state.used, limit - 1);
  assert.equal(state.remaining, 1);
  assert.equal(state.exhausted, false, "the last scan in the allowance must still be allowed");

  await recordScanUsage(id, null, "upload");
  state = (await getQuotaState(id))!;
  assert.equal(state.remaining, 0);
  assert.equal(state.exhausted, true);

  // Going over never reports a negative allowance.
  await recordScanUsage(id, null, "upload");
  assert.equal((await getQuotaState(id))!.remaining, 0);
});

test("the two tiers carry different allowances", async () => {
  const one = await subscriber("quota-t1@example.com", "tier1");
  const two = await subscriber("quota-t2@example.com", "tier2");
  assert.equal((await getQuotaState(one))!.limit, SCAN_QUOTAS.tier1);
  assert.equal((await getQuotaState(two))!.limit, SCAN_QUOTAS.tier2);
  assert.notEqual(SCAN_QUOTAS.tier1, SCAN_QUOTAS.tier2);
});

test("an unsubscribed account has no metered quota", async () => {
  const user = await createUser("quota-free@example.com", PASSWORD);
  assert.equal(await getQuotaState(user.id), null);
});

test("usage is recorded even when no project is attached", async () => {
  // This is the hole the ledger exists to close: a scan run without a
  // project API key never lands in the `scans` table, so counting stored
  // reports would let a subscriber take unlimited scans by omitting the key.
  const id = await subscriber("quota-noproject@example.com");
  await recordScanUsage(id, null, "upload");
  assert.equal((await getQuotaState(id))!.used, 1);
});

test("the paywall copy quotes the allowance the API actually enforces", () => {
  // These two live in different packages, so nothing but this check stops
  // them drifting — and drift here means quoting a customer one number and
  // charging them for another.
  const fs = require("fs") as typeof import("fs");
  const path = require("path") as typeof import("path");
  const copy = fs.readFileSync(
    path.join(__dirname, "..", "..", "frontend", "src", "plans.ts"),
    "utf8"
  );

  for (const [plan, limit] of Object.entries(SCAN_QUOTAS)) {
    assert.ok(
      copy.includes(`${limit} scans per month`),
      `frontend/src/plans.ts should advertise "${limit} scans per month" for ${plan}`
    );
  }

  // And must not still be advertising an unmetered plan.
  assert.ok(
    !/unlimited\s+(launch-readiness\s+)?scans/i.test(copy),
    "paywall copy must not promise unlimited scans while a quota is enforced"
  );
});

test("deleting a user leaves no orphaned scan_usage rows", async () => {
  const user = await createUser("orphan-usage@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "tier1", "active");
  await recordScanUsage(user.id, null, "upload");
  await recordScanUsage(user.id, null, "repo");

  // CAST + Number, exactly as the production queries do: PostgreSQL returns
  // COUNT(*) as bigint, which pg hands back as a string. Without this the
  // assertion compares '2' to 2 and fails on PostgreSQL while passing on
  // SQLite — the precise dialect trap this migration had to handle.
  const before = await db.get<{ n: number | string }>(
    "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scan_usage WHERE user_id = ?",
    [user.id]
  );
  assert.equal(Number(before?.n), 2);

  await deleteUser(user.id);

  // SQLite does not enforce the declared foreign keys, so nothing else would
  // have caught these rows pointing at a user that no longer exists.
  const after = await db.get<{ n: number | string }>(
    "SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scan_usage WHERE user_id = ?",
    [user.id]
  );
  assert.equal(Number(after?.n), 0);
});
