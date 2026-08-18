import { test } from "node:test";
import assert from "node:assert/strict";
import { createUser } from "../src/auth/users";
import { createSession, sweepExpiredSessions, resolveSession } from "../src/auth/sessions";
import { db } from "../src/db";

test("sweepExpiredSessions deletes only sessions past their expiry, leaving live ones alone", async () => {
  const user = await createUser("session-sweep@example.com", "correct horse battery staple");
  const expiredToken = createSession(user.id);

  // sessions.token stores a hash, not the raw token (see auth/sessions.ts)
  // — so to backdate this specific session's expiry, look up the row the
  // way the rest of the app is allowed to: there's exactly one session
  // for this user right now, so no ambiguity in which row to touch.
  const { token: storedValue } = db.prepare("SELECT token FROM sessions WHERE user_id = ?").get(user.id) as { token: string };
  db.prepare("UPDATE sessions SET expires_at = ? WHERE token = ?").run(new Date(Date.now() - 60_000).toISOString(), storedValue);

  const liveToken = createSession(user.id);

  const removed = sweepExpiredSessions();
  assert.ok(removed >= 1);

  assert.equal(resolveSession(expiredToken), null);
  assert.deepEqual(resolveSession(liveToken), { userId: user.id });
});

test("sweepExpiredSessions is a no-op when nothing is expired", async () => {
  const user = await createUser("session-sweep-noop@example.com", "correct horse battery staple");
  createSession(user.id);

  const before = (db.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(user.id) as { count: number }).count;
  sweepExpiredSessions();
  const after = (db.prepare("SELECT COUNT(*) as count FROM sessions WHERE user_id = ?").get(user.id) as { count: number }).count;

  assert.equal(after, before);
});
