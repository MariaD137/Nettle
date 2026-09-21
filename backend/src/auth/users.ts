import { db, newId } from "../db";
import { hashPassword, verifyPassword } from "./passwords";
import { hashToken } from "./tokenHash";
import crypto from "crypto";

export interface User {
  id: string;
  email: string;
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  billingAnchor: string | null;
  createdAt: string;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  plan: string;
  stripe_customer_id: string | null;
  subscription_status: string;
  billing_anchor: string | null;
  created_at: string;
}

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    plan: row.plan,
    stripeCustomerId: row.stripe_customer_id,
    subscriptionStatus: row.subscription_status,
    billingAnchor: row.billing_anchor,
    createdAt: row.created_at,
  };
}

export class EmailAlreadyRegisteredError extends Error {}

export async function createUser(email: string, password: string): Promise<User> {
  const existing = db.prepare("SELECT 1 FROM users WHERE email = ?").get(email);
  if (existing) throw new EmailAlreadyRegisteredError();

  const passwordHash = await hashPassword(password);
  const id = newId();
  const createdAt = new Date().toISOString();
  db.prepare("INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)").run(
    id,
    email,
    passwordHash,
    createdAt
  );
  return { id, email, plan: "free", stripeCustomerId: null, subscriptionStatus: "none", billingAnchor: null, createdAt };
}

export async function verifyCredentials(email: string, password: string): Promise<User | null> {
  const row = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as UserRow | undefined;
  if (!row) return null;
  const valid = await verifyPassword(password, row.password_hash);
  return valid ? toUser(row) : null;
}

export function getUserById(id: string): User | null {
  const row = db.prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
  return row ? toUser(row) : null;
}

export function getUserByEmail(email: string): User | null {
  const row = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as UserRow | undefined;
  return row ? toUser(row) : null;
}

export function setStripeCustomerId(userId: string, stripeCustomerId: string): void {
  db.prepare("UPDATE users SET stripe_customer_id = ? WHERE id = ?").run(stripeCustomerId, userId);
}

export function setSubscriptionStatus(userId: string, plan: string, status: string): void {
  db.prepare("UPDATE users SET plan = ?, subscription_status = ? WHERE id = ?").run(plan, status, userId);

  // Stamp the billing anchor the first time this account becomes active. It
  // is deliberately never overwritten: the monthly scan period is derived by
  // rolling this date forward, so moving it would silently reset someone's
  // usage mid-cycle.
  if (status === "active" || status === "trialing") {
    db.prepare(
      "UPDATE users SET billing_anchor = ? WHERE id = ? AND billing_anchor IS NULL"
    ).run(new Date().toISOString(), userId);
  }
}

export function getUserByStripeCustomerId(stripeCustomerId: string): User | null {
  const row = db.prepare("SELECT * FROM users WHERE stripe_customer_id = ?").get(stripeCustomerId) as
    | UserRow
    | undefined;
  return row ? toUser(row) : null;
}

export async function updatePassword(userId: string, newPassword: string): Promise<void> {
  const passwordHash = await hashPassword(newPassword);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, userId);
}

const RESET_TOKEN_LIFETIME_MS = 60 * 60 * 1000; // 1 hour

export function createPasswordResetToken(userId: string): string {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_TOKEN_LIFETIME_MS).toISOString();
  // Only the hash is stored: a reset token is a password-equivalent credential
  // for the lifetime of its window, so the database must not hold a replayable
  // copy. The raw value is returned to the caller for delivery and then dropped.
  db.prepare(
    "INSERT OR REPLACE INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)"
  ).run(hashToken(token), userId, expiresAt);
  return token;
}

export function resolvePasswordResetToken(token: string): { userId: string } | null {
  const tokenHash = hashToken(token);
  const row = db.prepare("SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?").get(tokenHash) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM password_resets WHERE token_hash = ?").run(tokenHash);
    return null;
  }
  return { userId: row.user_id };
}

export function consumePasswordResetToken(token: string): void {
  db.prepare("DELETE FROM password_resets WHERE token_hash = ?").run(hashToken(token));
}

/**
 * Drops every outstanding reset token for a user. Called once a password has
 * actually changed, so a second, still-valid reset link cannot be used to take
 * the account back afterwards.
 */
export function invalidatePasswordResetTokens(userId: string): void {
  db.prepare("DELETE FROM password_resets WHERE user_id = ?").run(userId);
}

/**
 * Removes reset tokens whose window has closed. Expiry is enforced on lookup;
 * this stops spent rows accumulating.
 */
export function purgeExpiredPasswordResetTokens(now = new Date()): number {
  const result = db.prepare("DELETE FROM password_resets WHERE expires_at < ?").run(now.toISOString());
  return Number(result.changes ?? 0);
}

export function updateEmail(userId: string, newEmail: string): User | null {
  const existing = db.prepare("SELECT 1 FROM users WHERE email = ? AND id != ?").get(newEmail, userId);
  if (existing) throw new EmailAlreadyRegisteredError();
  db.prepare("UPDATE users SET email = ? WHERE id = ?").run(newEmail, userId);
  return getUserById(userId);
}

export function deleteUser(userId: string): void {
  db.prepare("DELETE FROM password_resets WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  const projectIds = db.prepare("SELECT id FROM projects WHERE user_id = ?").all(userId) as unknown as { id: string }[];
  for (const p of projectIds) {
    db.prepare("DELETE FROM alerts WHERE project_id = ?").run(p.id);
    db.prepare("DELETE FROM events WHERE project_id = ?").run(p.id);
    db.prepare("DELETE FROM scans WHERE project_id = ?").run(p.id);
    db.prepare("DELETE FROM finding_statuses WHERE project_id = ?").run(p.id);
  }
  db.prepare("DELETE FROM projects WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM notification_preferences WHERE user_id = ?").run(userId);
  db.prepare("DELETE FROM users WHERE id = ?").run(userId);
}
