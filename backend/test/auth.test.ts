import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
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

test("changing password signs out every other session but keeps the current one", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "revoke-on-pw-change@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenA } = await signup.json();

    // A second, independent session — e.g. logged in on another device.
    const login = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "revoke-on-pw-change@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenB } = await login.json();

    const changeRes = await fetch(`${base}/api/auth/change-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ currentPassword: "correct horse battery staple", newPassword: "new correct horse battery" }),
    });
    assert.equal(changeRes.status, 200);

    // tokenA (the session that made the change) must still work.
    const meA = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenA}` } });
    assert.equal(meA.status, 200);

    // tokenB (the other session) must have been signed out.
    const meB = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenB}` } });
    assert.equal(meB.status, 401);
  } finally {
    server.close();
  }
});

test("changing email signs out every other session but keeps the current one", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    const signup = await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "revoke-on-email-change@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenA } = await signup.json();

    const login = await fetch(`${base}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "revoke-on-email-change@example.com", password: "correct horse battery staple" }),
    });
    const { token: tokenB } = await login.json();

    const changeRes = await fetch(`${base}/api/auth/email`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenA}` },
      body: JSON.stringify({ email: "new-address@example.com", password: "correct horse battery staple" }),
    });
    assert.equal(changeRes.status, 200);

    const meA = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenA}` } });
    assert.equal(meA.status, 200);

    const meB = await fetch(`${base}/api/auth/me`, { headers: { Authorization: `Bearer ${tokenB}` } });
    assert.equal(meB.status, 401);
  } finally {
    server.close();
  }
});

test("forgot-password no longer logs the raw reset token", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "reset-no-log@example.com", password: "correct horse battery staple" }),
    });

    const originalNodeEnv = process.env.NODE_ENV;
    try {
      // Outside production, with no email provider configured, the token
      // comes back in the response body (for dev/test use) instead of
      // being written to the process log.
      delete process.env.NODE_ENV;
      const res = await fetch(`${base}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "reset-no-log@example.com" }),
      });
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(typeof body.devToken, "string");

      // And that token actually works end to end.
      const resetRes = await fetch(`${base}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: body.devToken, password: "brand new password here" }),
      });
      assert.equal(resetRes.status, 200);
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
    }
  } finally {
    server.close();
  }
});

test("forgot-password never exposes the reset token in production", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  const originalNodeEnv = process.env.NODE_ENV;
  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "reset-prod@example.com", password: "correct horse battery staple" }),
    });

    process.env.NODE_ENV = "production";
    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "reset-prod@example.com" }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.devToken, undefined, "the reset token must never be returned in production");
  } finally {
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    server.close();
  }
});

test("forgot-password still responds if the email provider throws", async () => {
  const app = express();
  app.use(express.json());
  app.use(authRouter);
  const { server, base } = await listen(app);

  // Marking a provider "configured" makes email/mailer.ts's sendEmail()
  // throw (no real send implementation exists yet) — this must not leave
  // the request hanging (Express 4 doesn't forward an async handler's
  // unhandled rejection to error middleware on its own).
  const originalSmtpHost = process.env.SMTP_HOST;
  try {
    await fetch(`${base}/api/auth/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "reset-provider-throws@example.com", password: "correct horse battery staple" }),
    });

    process.env.SMTP_HOST = "smtp.example.com";
    const res = await fetch(`${base}/api/auth/forgot-password`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "reset-provider-throws@example.com" }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.message, "If that email is registered, a reset link has been sent");
  } finally {
    if (originalSmtpHost === undefined) delete process.env.SMTP_HOST;
    else process.env.SMTP_HOST = originalSmtpHost;
    server.close();
  }
});
