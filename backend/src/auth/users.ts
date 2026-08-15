import { db, newId } from "../db";
import { hashPassword, verifyPassword } from "./passwords";
import crypto from "crypto";

export interface User {
  id: string;
  email: string;
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  createdAt: string;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  plan: string;
  stripe_customer_id: string | null;
  subscription_status: string;
  created_at: string;
}

function toUser(row: UserRow): User {
  return {
    id: row.id,
    email: row.email,
    plan: row.plan,
    stripeCustomerId: row.stripe_customer_id,
    subscriptionStatus: row.subscription_status,
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
  return { id, email, plan: "free", stripeCustomerId: null, subscriptionStatus: "none", createdAt };
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
  db.prepare(
    "INSERT OR REPLACE INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)"
  ).run(token, userId, expiresAt);
  return token;
}

export function resolvePasswordResetToken(token: string): { userId: string } | null {
  const row = db.prepare("SELECT user_id, expires_at FROM password_resets WHERE token = ?").get(token) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM password_resets WHERE token = ?").run(token);
    return null;
  }
  return { userId: row.user_id };
}

export function consumePasswordResetToken(token: string): void {
  db.prepare("DELETE FROM password_resets WHERE token = ?").run(token);
}
