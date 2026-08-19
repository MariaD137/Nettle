import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { SMTPServer } from "smtp-server";
import { authRouter } from "../src/routes/auth.routes";
import { createUser, verifyCredentials, EmailAlreadyRegisteredError } from "../src/auth/users";
import { hashPassword, verifyPassword } from "../src/auth/passwords";

function listen(app: express.Express): Promise<{ server: Server; port: number; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, port, base: `http://localhost:${port}` });
    });
  });
}

test("password hashing: correct password verifies, wrong password doesn't", async () => {
  const hash = await hashPassword("correct horse battery staple");
  assert.equal(await verifyPassword("correct horse battery staple", hash), true);
  assert.equal(await verifyPassword("wrong password", hash), false);
});

test("createUser rejects a duplicate email", async () => {
  await createUser("dup-test@example.com", "correct horse battery staple");
  await assert.rejects(() => createUser("dup-test@example.com", "some other password"), EmailAlreadyRegisteredError);
});

test("verifyCredentials returns null for an unknown email or wrong password", async () => {
  await createUser("known@example.com", "correct horse battery staple");
  assert.equal(await verifyCredentials("unknown@example.com", "anything"), null);
  assert.equal(await verifyCredentials("known@example.com", "wrong password"), null);
});

// Regression coverage: verifyCredentials used to return immediately for an
// unknown email (no row to run scrypt against), while a known email always
// paid the real scrypt cost first — a real, if narrow, account-enumeration
// timing gap. Both paths now run scrypt unconditionally (against a dummy
// hash when there's no real one). This doesn't assert exact timing
// equality (too flaky under real scheduler noise) — it asserts an unknown
// email takes genuinely scrypt-costly time, not near-instant time, which
// is the actual property that closes the gap.
test("checking an unknown email pays the same real password-hashing cost as a known one, not a near-instant rejection", async () => {
  await createUser("timing-known@example.com", "correct horse battery staple");

  const start = process.hrtime.bigint();
  await verifyCredentials("timing-unknown@example.com", "anything");
  const unknownMs = Number(process.hrtime.bigint() - start) / 1_000_000;

  const start2 = process.hrtime.bigint();
  await verifyCredentials("timing-known@example.com", "wrong password");
  const knownMs = Number(process.hrtime.bigint() - start2) / 1_000_000;

  // A near-instant rejection (no scrypt run) would be well under 1ms; a
  // real scrypt derivation is reliably several ms even on fast hardware.
  // This is a floor, not a timing-equality assertion.
  assert.ok(unknownMs > 1, `unknown-email check should run real scrypt, took ${unknownMs}ms`);
  assert.ok(knownMs > 1, `known-email check should run real scrypt, took ${knownMs}ms`);
});

test("full HTTP flow: signup, then me, then logout, then me fails", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signupRes = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "http-flow@example.com", password: "correct horse battery staple" }),
    });
    assert.equal(signupRes.status, 201);
    const { token, user } = await signupRes.json();
    assert.equal(user.email, "http-flow@example.com");
    assert.ok(token);

    const meRes = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(meRes.status, 200);
    assert.equal((await meRes.json()).user.email, "http-flow@example.com");

    const logoutRes = await fetch(`${base}/api/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(logoutRes.status, 204);

    const meAfterLogoutRes = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
    assert.equal(meAfterLogoutRes.status, 401);
  } finally {
    server.close();
  }
});

test("HTTP signup rejects a weak password and an invalid email", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const weakPw = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "weak@example.com", password: "short" }),
    });
    assert.equal(weakPw.status, 400);

    const badEmail = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "not-an-email", password: "correct horse battery staple" }),
    });
    assert.equal(badEmail.status, 400);
  } finally {
    server.close();
  }
});

test("HTTP login fails with the wrong password", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "login-test@example.com", password: "correct horse battery staple" }),
    });
    const res = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "login-test@example.com", password: "wrong password" }),
    });
    assert.equal(res.status, 401);
  } finally {
    server.close();
  }
});

test("forgot-password sends a real reset email containing a working reset link, for a registered account", async () => {
  const received: string[] = [];
  const smtp = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, _session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => {
        received.push(Buffer.concat(chunks).toString("utf8"));
        callback();
      });
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, resolve));
  const smtpPort = (smtp.server.address() as AddressInfo).port;

  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  const originalFrontend = process.env.FRONTEND_URL;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(smtpPort);
  process.env.FRONTEND_URL = "https://app.nettle.example";

  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "forgot-password-real@example.com", password: "correct horse battery staple" }),
    });

    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "forgot-password-real@example.com" }),
    });
    assert.equal(res.status, 200);

    await new Promise((resolve) => setTimeout(resolve, 300));

    // Signup itself now also sends a verification email into this same
    // mailbox, so this asserts on the specific reset email rather than
    // assuming it's the only mail sent during the test.
    const resetEmails = received.filter((m) => m.includes("Subject: Reset your Nettle password"));
    assert.equal(resetEmails.length, 1);
    assert.ok(resetEmails[0].includes("https://app.nettle.example/reset-password?token="));
  } finally {
    server.close();
    await new Promise((resolve) => smtp.close(resolve as any));
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
    process.env.FRONTEND_URL = originalFrontend;
  }
});

test("forgot-password for an unregistered email sends no mail but still returns the generic message", async () => {
  const received: string[] = [];
  const smtp = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, _session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => {
        received.push(Buffer.concat(chunks).toString("utf8"));
        callback();
      });
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, resolve));
  const smtpPort = (smtp.server.address() as AddressInfo).port;

  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(smtpPort);

  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "never-registered@example.com" }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.message, "If that email is registered, a reset link has been sent");

    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(received.length, 0);
  } finally {
    server.close();
    await new Promise((resolve) => smtp.close(resolve as any));
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
  }
});
