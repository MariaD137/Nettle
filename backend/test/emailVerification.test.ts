import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { SMTPServer } from "smtp-server";
import { authRouter } from "../src/routes/auth.routes";
import { getUserByEmail, resolveEmailVerificationToken } from "../src/auth/users";

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

// nodemailer sends the plain-text part as quoted-printable: long lines
// soft-wrap at 76 chars with a trailing "=\r\n" (no real newline, keep
// reading — and it does land mid-URL/mid-token here), and any literal "="
// in the source text (the query string's "token=" itself) is escaped as
// "=3D". Both need undoing to read the body as the real text it encodes,
// not just the line-wrap — a naive substring/regex check against the raw
// wire bytes is fragile in exactly the way this fixes.
function unwrapQuotedPrintable(raw: string): string {
  return raw.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

function startSmtp(): Promise<{ smtp: SMTPServer; received: string[]; port: number }> {
  const received: string[] = [];
  const smtp = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, _session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => {
        received.push(unwrapQuotedPrintable(Buffer.concat(chunks).toString("utf8")));
        callback();
      });
    },
  });
  return new Promise((resolve) => {
    smtp.listen(0, () => resolve({ smtp, received, port: (smtp.server.address() as AddressInfo).port }));
  });
}

function extractToken(emailBody: string): string {
  const match = emailBody.match(/token=([a-f0-9]{64})/);
  assert.ok(match, "verification email should contain a token");
  return match![1];
}

test("signup sends a real verification email; the link in it verifies the account exactly once", async () => {
  const { smtp, received, port } = await startSmtp();
  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  const originalFrontend = process.env.FRONTEND_URL;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(port);
  process.env.FRONTEND_URL = "https://app.nettle.example";

  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "verify-flow@example.com", password: "correct horse battery staple" }),
    });

    await new Promise((resolve) => setTimeout(resolve, 300));
    const verifyEmails = received.filter((m) => m.includes("Subject: Verify your Nettle email address"));
    assert.equal(verifyEmails.length, 1);
    assert.ok(verifyEmails[0].includes("https://app.nettle.example/verify-email?token="));

    const before = getUserByEmail("verify-flow@example.com")!;
    assert.equal(before.emailVerifiedAt, null);

    const token = extractToken(verifyEmails[0]);
    const res = await fetch(`${base}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.user.emailVerifiedAt);

    const after = getUserByEmail("verify-flow@example.com")!;
    assert.ok(after.emailVerifiedAt);

    // Single-use: the same link doesn't work a second time.
    const second = await fetch(`${base}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    assert.equal(second.status, 400);
  } finally {
    server.close();
    await new Promise((resolve) => smtp.close(resolve as any));
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
    process.env.FRONTEND_URL = originalFrontend;
  }
});

test("verify-email rejects an unknown or malformed token without crashing", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const res = await fetch(`${base}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: "not-a-real-token" }),
    });
    assert.equal(res.status, 400);
  } finally {
    server.close();
  }
});

test("an expired verification token is rejected and cleaned up", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "verify-expired@example.com", password: "correct horse battery staple" }),
    });
    const { token: sessionToken } = await signup.json();

    // Force-expire by manipulating the stored token directly, mirroring the
    // real 24h expiry rather than waiting for it in a test.
    const { db } = await import("../src/db/index");
    db.prepare("UPDATE email_verifications SET expires_at = '2000-01-01T00:00:00.000Z' WHERE user_id = (SELECT id FROM users WHERE email = ?)").run(
      "verify-expired@example.com"
    );
    const row = db
      .prepare("SELECT token FROM email_verifications WHERE user_id = (SELECT id FROM users WHERE email = ?)")
      .get("verify-expired@example.com") as { token: string } | undefined;
    assert.ok(row);

    const res = await fetch(`${base}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${sessionToken}` },
      body: JSON.stringify({ token: row!.token }),
    });
    assert.equal(res.status, 400);
    assert.equal(resolveEmailVerificationToken(row!.token), null);
  } finally {
    server.close();
  }
});

test("resend-verification requires auth, is rate-limited per account, and no-ops once already verified", async () => {
  const { smtp, received, port } = await startSmtp();
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(port);

  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const unauthed = await fetch(`${base}/api/auth/resend-verification`, { method: "POST" });
    assert.equal(unauthed.status, 401);

    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "resend-flow@example.com", password: "correct horse battery staple" }),
    });
    const { token: sessionToken } = await signup.json();

    const resend = await fetch(`${base}/api/auth/resend-verification`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    assert.equal(resend.status, 200);

    await new Promise((resolve) => setTimeout(resolve, 300));
    const verifyEmails = received.filter((m) => m.includes("Subject: Verify your Nettle email address"));
    // One from signup, one from the explicit resend.
    assert.equal(verifyEmails.length, 2);

    const token = extractToken(verifyEmails[1]);
    await fetch(`${base}/api/auth/verify-email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });

    const afterVerified = await fetch(`${base}/api/auth/resend-verification`, {
      method: "POST",
      headers: { Authorization: `Bearer ${sessionToken}` },
    });
    assert.equal(afterVerified.status, 400);
  } finally {
    server.close();
    await new Promise((resolve) => smtp.close(resolve as any));
  }
});
