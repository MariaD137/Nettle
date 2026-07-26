import { Router } from "express";
import { createUser, verifyCredentials, getUserById, EmailAlreadyRegisteredError } from "../auth/users";
import { createSession, destroySession } from "../auth/sessions";
import { requireAuth } from "../auth/middleware";

export const authRouter = Router();

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

authRouter.post("/api/auth/signup", async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!EMAIL_PATTERN.test(email)) {
    return res.status(400).json({ error: "Provide a valid email address" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  try {
    const user = await createUser(email, password);
    const token = createSession(user.id);
    res.status(201).json({ token, user });
  } catch (err) {
    if (err instanceof EmailAlreadyRegisteredError) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    throw err;
  }
});

authRouter.post("/api/auth/login", async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  const user = await verifyCredentials(email, password);
  if (!user) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }
  const token = createSession(user.id);
  res.json({ token, user });
});

authRouter.post("/api/auth/logout", requireAuth, (req, res) => {
  const header = req.header("authorization") || "";
  const token = header.slice("Bearer ".length);
  destroySession(token);
  res.status(204).end();
});

authRouter.get("/api/auth/me", requireAuth, (req, res) => {
  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });
  res.json({ user });
});
