import { Router } from "express";
import {
  createUser,
  verifyCredentials,
  getUserById,
  getUserByEmail,
  updatePassword,
  updateEmail,
  deleteUser,
  createPasswordResetToken,
  resolvePasswordResetToken,
  consumePasswordResetToken,
  EmailAlreadyRegisteredError,
} from "../auth/users";
import { createSession, destroySession, listSessions, destroyAllSessions, destroySessionByPrefix } from "../auth/sessions";
import { requireAuth } from "../auth/middleware";
import { rateLimit } from "../middleware/rateLimit";

export const authRouter = Router();

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: "Too many authentication attempts — try again in a few minutes",
});

authRouter.post("/api/auth/signup", authLimiter, async (req, res) => {
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

authRouter.post("/api/auth/login", authLimiter, async (req, res) => {
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

authRouter.post("/api/auth/forgot-password", authLimiter, (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!EMAIL_PATTERN.test(email)) {
    return res.status(400).json({ error: "Provide a valid email address" });
  }

  const user = getUserByEmail(email);
  if (user) {
    const resetToken = createPasswordResetToken(user.id);
    console.log(`[password-reset] token for ${email}: ${resetToken}`);
  }

  res.json({ message: "If that email is registered, a reset link has been sent" });
});

authRouter.post("/api/auth/reset-password", authLimiter, async (req, res) => {
  const token = typeof req.body?.token === "string" ? req.body.token : "";
  const newPassword = typeof req.body?.password === "string" ? req.body.password : "";

  if (!token) {
    return res.status(400).json({ error: "Reset token is required" });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  const resolved = resolvePasswordResetToken(token);
  if (!resolved) {
    return res.status(400).json({ error: "Invalid or expired reset token" });
  }

  await updatePassword(resolved.userId, newPassword);
  consumePasswordResetToken(token);

  res.json({ message: "Password has been reset — you can now log in" });
});

authRouter.post("/api/auth/change-password", requireAuth, async (req, res) => {
  const currentPassword = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
  const newPassword = typeof req.body?.newPassword === "string" ? req.body.newPassword : "";

  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, currentPassword);
  if (!valid) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  await updatePassword(req.userId!, newPassword);
  res.json({ message: "Password updated" });
});

authRouter.patch("/api/auth/email", requireAuth, async (req, res) => {
  const newEmail = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!EMAIL_PATTERN.test(newEmail)) {
    return res.status(400).json({ error: "Provide a valid email address" });
  }

  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, password);
  if (!valid) {
    return res.status(401).json({ error: "Password is incorrect" });
  }

  try {
    const updated = updateEmail(req.userId!, newEmail);
    res.json({ user: updated });
  } catch (err) {
    if (err instanceof EmailAlreadyRegisteredError) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    throw err;
  }
});

authRouter.get("/api/auth/sessions", requireAuth, (req, res) => {
  const header = req.header("authorization") || "";
  const currentToken = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : undefined;
  const sessions = listSessions(req.userId!, currentToken);
  res.json({ sessions });
});

authRouter.delete("/api/auth/sessions/:tokenPrefix", requireAuth, (req, res) => {
  const destroyed = destroySessionByPrefix(req.userId!, req.params.tokenPrefix);
  if (!destroyed) return res.status(404).json({ error: "Session not found" });
  res.status(204).end();
});

authRouter.post("/api/auth/sessions/revoke-all", requireAuth, (req, res) => {
  destroyAllSessions(req.userId!);
  const newToken = createSession(req.userId!);
  res.json({ token: newToken, message: "All other sessions have been revoked" });
});

authRouter.delete("/api/auth/account", requireAuth, async (req, res) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const user = getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, password);
  if (!valid) {
    return res.status(401).json({ error: "Password is incorrect" });
  }

  deleteUser(req.userId!);
  res.status(204).end();
});
