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
