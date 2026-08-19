import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createSession, resolveSession, listSessions, destroySessionByPrefix, destroyAllSessions } from "../src/auth/sessions";
import { authRouter } from "../src/routes/auth.routes";
import { db } from "../src/db";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

test("a session token is never stored in the sessions table at rest", async () => {
  const user = await createUser("session-at-rest@example.com", "correct horse battery staple");
  const token = await createSession(user.id);

  const row = (await db.prepare("SELECT token FROM sessions WHERE user_id = ?").get(user.id)) as { token: string };
  assert.notEqual(row.token, token, "the raw token must never appear in the stored row");
  assert.equal(row.token.length, 64, "expected a 64-hex-char SHA-256 digest in its place");

  // The stored value must still round-trip correctly through the real API.
  assert.deepEqual(await resolveSession(token), { userId: user.id });
});

test("listSessions marks the caller's own session current and shows a stable prefix per session", async () => {
  const user = await createUser("session-list@example.com", "correct horse battery staple");
  const tokenA = await createSession(user.id);
  const tokenB = await createSession(user.id);

  const asA = await listSessions(user.id, tokenA);
  assert.equal(asA.length, 2);
  assert.equal(asA.filter((s) => s.current).length, 1);
  const aEntryFromA = asA.find((s) => s.current)!;
  const bEntryFromA = asA.find((s) => !s.current)!;

  const asB = await listSessions(user.id, tokenB);
  const bEntryFromB = asB.find((s) => s.current)!;
  const aEntryFromB = asB.find((s) => !s.current)!;

  // Same underlying sessions, viewed from either side — the prefix each
  // one shows is stable regardless of who's asking or which is "current".
  assert.equal(aEntryFromA.tokenPrefix, aEntryFromB.tokenPrefix);
  assert.equal(bEntryFromA.tokenPrefix, bEntryFromB.tokenPrefix);
  assert.notEqual(aEntryFromA.tokenPrefix, bEntryFromA.tokenPrefix);
});

test("destroySessionByPrefix revokes the exact session the prefix identifies, not others", async () => {
  const user = await createUser("session-revoke-prefix@example.com", "correct horse battery staple");
  const tokenA = await createSession(user.id);
  const tokenB = await createSession(user.id);

  const listing = await listSessions(user.id, tokenA);
  const targetPrefix = listing.find((s) => s.current)!.tokenPrefix;

  const destroyed = await destroySessionByPrefix(user.id, targetPrefix);
  assert.equal(destroyed, true);

  assert.equal(await resolveSession(tokenA), null);
  assert.deepEqual(await resolveSession(tokenB), { userId: user.id });
});

test("destroySessionByPrefix returns false for a prefix that doesn't match any session", async () => {
  const user = await createUser("session-revoke-miss@example.com", "correct horse battery staple");
  await createSession(user.id);
  assert.equal(await destroySessionByPrefix(user.id, "ffffffff"), false);
});

test("destroyAllSessions revokes every session for the account and no one else's", async () => {
  const user = await createUser("session-revoke-all@example.com", "correct horse battery staple");
  const other = await createUser("session-revoke-all-other@example.com", "correct horse battery staple");
  const tokenA = await createSession(user.id);
  const tokenB = await createSession(user.id);
  const otherToken = await createSession(other.id);

  await destroyAllSessions(user.id);

  assert.equal(await resolveSession(tokenA), null);
  assert.equal(await resolveSession(tokenB), null);
  assert.deepEqual(await resolveSession(otherToken), { userId: other.id });
});

test("HTTP: GET /api/auth/sessions, DELETE by prefix, and POST revoke-all all work end-to-end", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "session-http@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenA } = await signup.json();

    const login = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "session-http@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenB } = await login.json();

    const list = await fetch(`${base}/api/auth/sessions`, { headers: { Authorization: `Bearer ${tokenA}` } });
    assert.equal(list.status, 200);
    const { sessions } = await list.json();
    assert.equal(sessions.length, 2);
    const currentEntry = sessions.find((s: any) => s.current);
    assert.ok(currentEntry);

    const del = await fetch(`${base}/api/auth/sessions/${encodeURIComponent(currentEntry.tokenPrefix)}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(del.status, 204);

    // tokenA's own session was just deleted using tokenB's auth — tokenA
    // itself should now be rejected.
    const afterDelete = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenA}` } });
    assert.equal(afterDelete.status, 401);

    const revokeAll = await fetch(`${base}/api/auth/sessions/revoke-all`, {
      method: "POST",
      headers: { Authorization: `Bearer ${tokenB}` },
    });
    assert.equal(revokeAll.status, 200);
    const { token: freshToken } = await revokeAll.json();

    const afterRevokeAll = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenB}` } });
    assert.equal(afterRevokeAll.status, 401, "the old token must be dead once every session was revoked");

    const withFreshToken = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${freshToken}` } });
    assert.equal(withFreshToken.status, 200, "revoke-all mints a fresh session for the caller so they aren't logged out too");
  } finally {
    server.close();
  }
});
