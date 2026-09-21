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
  invalidatePasswordResetTokens,
  EmailAlreadyRegisteredError,
} from "../auth/users";
import { createSession, destroySession, listSessions, destroyAllSessions, destroyOtherSessions, destroySessionByPrefix } from "../auth/sessions";
import { deliverPasswordResetLink } from "../notifications/passwordResetDelivery";
import { requireAuth } from "../auth/middleware";
import { rateLimit } from "../middleware/rateLimit";

export const authRouter = Router();

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Each auth route gets its own scope, so a caller who exhausts the signup
// limit is not also blocked from logging in, and vice versa. Keyed by IP
// (the default keyFn) — that's the right identity for login/signup abuse:
// credential stuffing and mass account creation are IP-cheap for an
// attacker to spread across many source addresses, but IP-keying is still
// the correct first line of defense and matches how these endpoints were
// throttled before.
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: "Too many signup attempts — try again in a few minutes",
  scope: "auth:signup",
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: "Too many login attempts — try again in a few minutes",
  scope: "auth:login",
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: "Too many password reset requests — try again in a few minutes",
  scope: "auth:forgot-password",
});

/**
 * A second, per-email limiter layered on top of the IP-based one above.
 *
 * IP-keying alone does not stop a distinct abuse pattern here: bombarding
 * ONE target address with reset emails from many different IPs (a botnet, a
 * rotating proxy pool). Once real email delivery is wired up (see
 * notifications/passwordResetDelivery.ts), that pattern spams a real inbox
 * and burns real send quota, no matter how the IP-based counter is spread
 * across attacker sources. Deliberately tighter and longer-windowed than the
 * per-IP limit, since five requests for the same address in an hour is
 * already unusual for a legitimate user (who has no reason to ask twice in
 * quick succession — the first email is still valid for an hour).
 *
 * Not applied to login: a per-account login limiter is a known anti-pattern
 * — it lets an attacker who merely knows a victim's email address lock that
 * victim out by deliberately tripping it, which is worse than the brute-force
 * risk it would guard against (session tokens/passwords are hashed and
 * scrypt-slowed regardless).
 */
const forgotPasswordPerEmailLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  maxRequests: 5,
  message: "Too many password reset requests for this address — try again later",
  scope: "auth:forgot-password:email",
  keyFn: (req) => {
    const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
    return email || null;
  },
});

const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  maxRequests: 15,
  message: "Too many reset attempts — try again in a few minutes",
  scope: "auth:reset-password",
});


authRouter.post("/api/auth/signup", signupLimiter, async (req, res) => {
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
    const token = await createSession(user.id);
    res.status(201).json({ token, user });
  } catch (err) {
    if (err instanceof EmailAlreadyRegisteredError) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    throw err;
  }
});

authRouter.post("/api/auth/login", loginLimiter, async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  const user = await verifyCredentials(email, password);
  if (!user) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }
  const token = await createSession(user.id);
  res.json({ token, user });
});

authRouter.post("/api/auth/logout", requireAuth, async (req, res) => {
  const header = req.header("authorization") || "";
  const token = header.slice("Bearer ".length);
  await destroySession(token);
  res.status(204).end();
});

authRouter.get("/api/auth/me", requireAuth, async (req, res) => {
  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });
  res.json({ user });
});

authRouter.post("/api/auth/forgot-password", forgotPasswordLimiter, forgotPasswordPerEmailLimiter, async (req, res) => {
  const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  if (!EMAIL_PATTERN.test(email)) {
    return res.status(400).json({ error: "Provide a valid email address" });
  }

  const user = await getUserByEmail(email);
  if (user) {
    const resetToken = await createPasswordResetToken(user.id);
    // The token goes to the delivery boundary and nowhere else. It is never
    // logged and never returned in the response: doing either would hand
    // account takeover to anyone who can read logs or guess an address.
    try {
      deliverPasswordResetLink(email, resetToken);
    } catch (err) {
      // A delivery failure must not change the response, or the difference
      // becomes an account-enumeration oracle.
      console.error(`[password-reset] delivery failed: ${(err as Error).message}`);
    }
  }

  // Identical response whether or not the address is registered.
  res.json({ message: "If that email is registered, a reset link has been sent" });
});

authRouter.post("/api/auth/reset-password", resetPasswordLimiter, async (req, res) => {
  const token = typeof req.body?.token === "string" ? req.body.token : "";
  const newPassword = typeof req.body?.password === "string" ? req.body.password : "";

  if (!token) {
    return res.status(400).json({ error: "Reset token is required" });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  const resolved = await resolvePasswordResetToken(token);
  if (!resolved) {
    return res.status(400).json({ error: "Invalid or expired reset token" });
  }

  await updatePassword(resolved.userId, newPassword);
  await consumePasswordResetToken(token);
  // Every existing session dies with the old password. A reset is the
  // recovery path for a compromised account, so leaving the attacker's
  // session alive would defeat the point of it. Any other outstanding reset
  // link is burned too, so it cannot be used to take the account straight back.
  await destroyAllSessions(resolved.userId);
  await invalidatePasswordResetTokens(resolved.userId);

  res.json({ message: "Password has been reset — you can now log in" });
});

authRouter.post("/api/auth/change-password", requireAuth, async (req, res) => {
  const currentPassword = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
  const newPassword = typeof req.body?.newPassword === "string" ? req.body.newPassword : "";

  if (newPassword.length < 8) {
    return res.status(400).json({ error: "New password must be at least 8 characters" });
  }

  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, currentPassword);
  if (!valid) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }

  await updatePassword(req.userId!, newPassword);
  // Other sessions are revoked, the caller's own is kept: the person changing
  // their password stays signed in here, while any session an attacker holds
  // stops working. Outstanding reset links are burned for the same reason.
  const header = req.header("authorization") || "";
  const currentToken = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
  const revoked = currentToken ? await destroyOtherSessions(req.userId!, currentToken) : await destroyAllSessions(req.userId!);
  await invalidatePasswordResetTokens(req.userId!);

  res.json({ message: "Password updated", revokedSessions: typeof revoked === "number" ? revoked : undefined });
});

authRouter.patch("/api/auth/email", requireAuth, async (req, res) => {
  const newEmail = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
  const password = typeof req.body?.password === "string" ? req.body.password : "";

  if (!EMAIL_PATTERN.test(newEmail)) {
    return res.status(400).json({ error: "Provide a valid email address" });
  }

  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, password);
  if (!valid) {
    return res.status(401).json({ error: "Password is incorrect" });
  }

  try {
    const updated = await updateEmail(req.userId!, newEmail);
    res.json({ user: updated });
  } catch (err) {
    if (err instanceof EmailAlreadyRegisteredError) {
      return res.status(409).json({ error: "An account with this email already exists" });
    }
    throw err;
  }
});

authRouter.get("/api/auth/sessions", requireAuth, async (req, res) => {
  const header = req.header("authorization") || "";
  const currentToken = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : undefined;
  const sessions = await listSessions(req.userId!, currentToken);
  res.json({ sessions });
});

authRouter.delete("/api/auth/sessions/:tokenPrefix", requireAuth, async (req, res) => {
  const destroyed = await destroySessionByPrefix(req.userId!, req.params.tokenPrefix);
  if (!destroyed) return res.status(404).json({ error: "Session not found" });
  res.status(204).end();
});

authRouter.post("/api/auth/sessions/revoke-all", requireAuth, async (req, res) => {
  await destroyAllSessions(req.userId!);
  const newToken = await createSession(req.userId!);
  res.json({ token: newToken, message: "All other sessions have been revoked" });
});

authRouter.delete("/api/auth/account", requireAuth, async (req, res) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const user = await getUserById(req.userId!);
  if (!user) return res.status(401).json({ error: "Invalid session" });

  const valid = await verifyCredentials(user.email, password);
  if (!valid) {
    return res.status(401).json({ error: "Password is incorrect" });
  }

  await deleteUser(req.userId!);
  res.status(204).end();
});
