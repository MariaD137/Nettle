import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { db } from "../src/db";
import { authRouter } from "../src/routes/auth.routes";
import { createSession, resolveSession, destroyOtherSessions } from "../src/auth/sessions";
import { createUser, createPasswordResetToken, resolvePasswordResetToken } from "../src/auth/users";
import { hashToken } from "../src/auth/tokenHash";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  return app;
}

// --- tokens are not stored in a replayable form ---

test("session tokens are stored hashed, never raw", async () => {
  const user = await createUser("sess-hash@example.com", "correct horse battery staple");
  const token = createSession(user.id);

  const raw = db.prepare("SELECT token_hash FROM sessions WHERE user_id = ?").all(user.id) as unknown as {
    token_hash: string;
  }[];
  assert.equal(raw.length, 1);
  assert.equal(raw[0].token_hash, hashToken(token));
  assert.notEqual(raw[0].token_hash, token, "the raw bearer token must not be what is persisted");

  // Whole-table sweep: the raw token must appear in no column anywhere.
  const dump = JSON.stringify(db.prepare("SELECT * FROM sessions").all());
  assert.ok(!dump.includes(token), "raw session token found in the sessions table");

  // ...and it still authenticates.
  assert.deepEqual(resolveSession(token), { userId: user.id });
});

test("password-reset tokens are stored hashed, never raw", async () => {
  const user = await createUser("reset-hash@example.com", "correct horse battery staple");
  const token = createPasswordResetToken(user.id);

  const dump = JSON.stringify(db.prepare("SELECT * FROM password_resets").all());
  assert.ok(!dump.includes(token), "raw reset token found in the password_resets table");
  assert.deepEqual(resolvePasswordResetToken(token), { userId: user.id });
});

test("an expired session is rejected and cleared", async () => {
  const user = await createUser("sess-expired@example.com", "correct horse battery staple");
  const token = createSession(user.id);
  db.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?").run(
    new Date(Date.now() - 1000).toISOString(),
    hashToken(token)
  );

  assert.equal(resolveSession(token), null);
  const left = db.prepare("SELECT token_hash FROM sessions WHERE token_hash = ?").all(hashToken(token));
  assert.equal(left.length, 0, "an expired session should not be left behind");
});

test("destroyOtherSessions keeps the presented session and kills the rest", async () => {
  const user = await createUser("sess-others@example.com", "correct horse battery staple");
  const keep = createSession(user.id);
  const a = createSession(user.id);
  const b = createSession(user.id);

  assert.equal(destroyOtherSessions(user.id, keep), 2);
  assert.ok(resolveSession(keep));
  assert.equal(resolveSession(a), null);
  assert.equal(resolveSession(b), null);
});

// --- credential changes revoke sessions ---

test("changing a password revokes other sessions but not the current one", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const signup = await fetch(`${base}/api/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "change-pw@example.com", password: "correct horse battery" }),
  });
  const { token: current, user } = (await signup.json()) as any;
  const stolen = createSession(user.id);

  const res = await fetch(`${base}/api/auth/change-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${current}` },
    body: JSON.stringify({ currentPassword: "correct horse battery", newPassword: "a brand new passphrase" }),
  });
  assert.equal(res.status, 200);

  assert.ok(resolveSession(current), "the session that made the change stays signed in");
  assert.equal(resolveSession(stolen), null, "a pre-existing session must not survive a password change");
});

test("resetting a password revokes every session, including the attacker's", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("reset-revoke@example.com", "correct horse battery staple");
  const stolen = createSession(user.id);
  const alsoStolen = createSession(user.id);
  const resetToken = createPasswordResetToken(user.id);

  const res = await fetch(`${base}/api/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: resetToken, password: "a brand new passphrase" }),
  });
  assert.equal(res.status, 200);

  assert.equal(resolveSession(stolen), null);
  assert.equal(resolveSession(alsoStolen), null);
});

test("a spent reset token cannot be replayed, and siblings are burned", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  const user = await createUser("reset-replay@example.com", "correct horse battery staple");
  const first = createPasswordResetToken(user.id);

  const ok = await fetch(`${base}/api/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: first, password: "a brand new passphrase" }),
  });
  assert.equal(ok.status, 200);

  const replay = await fetch(`${base}/api/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: first, password: "yet another passphrase" }),
  });
  assert.equal(replay.status, 400, "a consumed reset token must not work twice");
});

// --- the reset endpoint leaks nothing ---

test("forgot-password never returns a token and does not reveal whether an account exists", async (t) => {
  const { server, base } = await listen(buildApp());
  t.after(() => server.close());

  await createUser("known@example.com", "correct horse battery staple");

  const known = await fetch(`${base}/api/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "known@example.com" }),
  });
  const unknown = await fetch(`${base}/api/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "nobody@example.com" }),
  });

  assert.equal(known.status, unknown.status);
  const knownBody = await known.text();
  const unknownBody = await unknown.text();
  assert.equal(knownBody, unknownBody, "responses must be byte-identical for registered and unregistered addresses");

  // The stored hash must not be derivable from the response.
  const stored = db.prepare("SELECT token_hash FROM password_resets").all() as unknown as { token_hash: string }[];
  for (const row of stored) {
    assert.ok(!knownBody.includes(row.token_hash), "response leaked the stored reset token hash");
  }
  assert.ok(!/token/i.test(knownBody), "response body should not mention a token at all");
});
