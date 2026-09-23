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
  reserveScanSlot,
} from "../src/billing/scanQuota";

const PASSWORD = "correct horse battery staple";

async function subscriber(email: string, plan: "build" | "protect" = "build") {
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
  await setSubscriptionStatus(id, "protect", "active");
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
  assert.equal((await getQuotaState(bob))!.remaining, SCAN_QUOTAS.build);
});

test("quota state reports remaining and flips to exhausted at the limit", async () => {
  const id = await subscriber("quota-exhaust@example.com");
  const limit = SCAN_QUOTAS.build;

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

test("BUILD has a finite allowance, PROTECT is unlimited/fair-use, FREE has none", async () => {
  const build = await subscriber("quota-build@example.com", "build");
  const protect = await subscriber("quota-protect@example.com", "protect");
  const free = await createUser("quota-free-named@example.com", PASSWORD);

  const buildState = (await getQuotaState(build))!;
  assert.equal(buildState.limit, SCAN_QUOTAS.build);
  assert.equal(buildState.exhausted, false);

  const protectState = (await getQuotaState(protect))!;
  assert.equal(protectState.limit, null, "unlimited/fair-use is represented as null, never a large number");
  assert.equal(protectState.remaining, null);
  assert.equal(protectState.exhausted, false);

  const freeState = (await getQuotaState(free.id))!;
  assert.equal(freeState.limit, 0, "FREE has no scan access at all");
  assert.equal(freeState.remaining, 0);
  assert.equal(freeState.exhausted, true, "0 used out of a limit of 0 is still exhausted — FREE can never scan");
});

test("a named account always has a quota state — FREE included, not just paid plans", async () => {
  const user = await createUser("quota-free-real@example.com", PASSWORD);
  const state = await getQuotaState(user.id);
  assert.notEqual(state, null, "FREE is a real reachable dashboard state now, not turned away before reaching here");
  assert.equal(state!.limit, 0);
});

test("getQuotaState returns null only for a user that doesn't exist", async () => {
  assert.equal(await getQuotaState("00000000-0000-0000-0000-000000000000"), null);
});

test("usage is recorded even when no project is attached", async () => {
  // This is the hole the ledger exists to close: a scan run without a
  // project API key never lands in the `scans` table, so counting stored
  // reports would let a subscriber take unlimited scans by omitting the key.
  const id = await subscriber("quota-noproject@example.com");
  await recordScanUsage(id, null, "upload");
  assert.equal((await getQuotaState(id))!.used, 1);
});

test("the paywall copy quotes the BUILD allowance the API actually enforces", () => {
  // These two live in different packages, so nothing but this check stops
  // them drifting — and drift here means quoting a customer one number and
  // charging them for another.
  const fs = require("fs") as typeof import("fs");
  const path = require("path") as typeof import("path");
  const copy = fs.readFileSync(
    path.join(__dirname, "..", "..", "frontend", "src", "plans.ts"),
    "utf8"
  );

  assert.ok(
    copy.includes(`${SCAN_QUOTAS.build} scans per month`),
    `frontend/src/plans.ts should advertise "${SCAN_QUOTAS.build} scans per month" for BUILD`
  );

  // PROTECT is genuinely unlimited/fair-use now — unlike the old two-finite-
  // tiers model, the copy SHOULD say so.
  assert.ok(
    /unlimited.{0,20}fair-use scans/i.test(copy),
    "paywall copy must advertise PROTECT's unlimited/fair-use scanning"
  );
});

test("deleting a user leaves no orphaned scan_usage rows", async () => {
  const user = await createUser("orphan-usage@example.com", "correct horse battery staple");
  await setSubscriptionStatus(user.id, "build", "active");
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

// --- reserveScanSlot: the atomic enforcement primitive ---------------------

test("reserveScanSlot allows exactly up to the limit and rejects beyond it", async () => {
  const id = await subscriber("reserve-basic@example.com");
  const limit = 3;

  assert.equal(await reserveScanSlot(id, limit), true);
  assert.equal(await reserveScanSlot(id, limit), true);
  assert.equal(await reserveScanSlot(id, limit), true);
  assert.equal(await reserveScanSlot(id, limit), false, "the 4th reservation against a limit of 3 must fail");
  assert.equal(await reserveScanSlot(id, limit), false, "still rejected on further attempts, not just the first overage");
});

test("reserveScanSlot: concurrent requests near the limit cannot both win the final slot", async () => {
  const id = await subscriber("reserve-race@example.com");
  const limit = 5;

  // 4 reservations up front, leaving exactly one slot.
  for (let i = 0; i < 4; i++) assert.equal(await reserveScanSlot(id, limit), true);

  // Fire 10 concurrent reservation attempts at the single remaining slot —
  // the scenario the master spec calls out explicitly: two (or more)
  // simultaneous scan requests must not both consume the final available
  // scan. Exactly one of these must win.
  const results = await Promise.all(Array.from({ length: 10 }, () => reserveScanSlot(id, limit)));
  const wins = results.filter(Boolean).length;
  assert.equal(wins, 1, `expected exactly 1 of 10 concurrent requests to win the last slot, got ${wins}`);
});

test("reserveScanSlot is scoped per account — one account racing never affects another's allowance", async () => {
  const alice = await subscriber("reserve-alice@example.com");
  const bob = await subscriber("reserve-bob@example.com");
  const limit = 2;

  const aliceResults = await Promise.all(Array.from({ length: 5 }, () => reserveScanSlot(alice, limit)));
  assert.equal(aliceResults.filter(Boolean).length, 2);

  // Bob's allowance is untouched by Alice's burst.
  assert.equal(await reserveScanSlot(bob, limit), true);
  assert.equal(await reserveScanSlot(bob, limit), true);
  assert.equal(await reserveScanSlot(bob, limit), false);
});
