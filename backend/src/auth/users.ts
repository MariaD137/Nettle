import { db, newId } from "../db";
import { hashPassword, verifyPassword } from "./passwords";

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
