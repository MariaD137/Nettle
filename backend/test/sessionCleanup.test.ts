import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { createSession, sweepExpiredSessions, resolveSession } from "../src/auth/sessions";
import { db } from "../src/db";

test("sweepExpiredSessions deletes only sessions past their expiry, leaving live ones alone", async () => {
  const user = await createUser("session-sweep@example.com", "correct horse battery staple");
  const expiredToken = await createSession(user.id);

  // sessions.token stores a hash, not the raw token (see auth/sessions.ts)
  // — so to backdate this specific session's expiry, look up the row the
  // way the rest of the app is allowed to: there's exactly one session
  // for this user right now, so no ambiguity in which row to touch.
  const { token: storedValue } = (await db.prepare("SELECT token FROM sessions WHERE user_id = ?").get(user.id)) as { token: string };
  await db.prepare("UPDATE sessions SET expires_at = ? WHERE token = ?").run(new Date(Date.now() - 60_000).toISOString(), storedValue);

  const liveToken = await createSession(user.id);

  const removed = await sweepExpiredSessions();
  assert.ok(removed >= 1);

  assert.equal(await resolveSession(expiredToken), null);
  assert.deepEqual(await resolveSession(liveToken), { userId: user.id });
});

test("sweepExpiredSessions is a no-op when nothing is expired", async () => {
  const user = await createUser("session-sweep-noop@example.com", "correct horse battery staple");
  await createSession(user.id);

  const before = Number((((await db.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(user.id)) as { count: number | string }).count));
  await sweepExpiredSessions();
  const after = Number((((await db.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(user.id)) as { count: number | string }).count));

  assert.equal(after, before);
});
