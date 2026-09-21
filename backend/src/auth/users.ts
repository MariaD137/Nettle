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
  const existing = await db.get("SELECT 1 AS present FROM users WHERE email = ?", [email]);
  if (existing) throw new EmailAlreadyRegisteredError();

  const passwordHash = await hashPassword(password);
  const id = newId();
  const createdAt = new Date().toISOString();
  await db.run("INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)", [
    id,
    email,
    passwordHash,
    createdAt,
  ]);
  return { id, email, plan: "free", stripeCustomerId: null, subscriptionStatus: "none", billingAnchor: null, createdAt };
}

export async function verifyCredentials(email: string, password: string): Promise<User | null> {
  const row = await db.get<UserRow>("SELECT * FROM users WHERE email = ?", [email]);
  if (!row) return null;
  const valid = await verifyPassword(password, row.password_hash);
  return valid ? toUser(row) : null;
}

export async function getUserById(id: string): Promise<User | null> {
  const row = await db.get<UserRow>("SELECT * FROM users WHERE id = ?", [id]);
  return row ? toUser(row) : null;
}

export async function getUserByEmail(email: string): Promise<User | null> {
  const row = await db.get<UserRow>("SELECT * FROM users WHERE email = ?", [email]);
  return row ? toUser(row) : null;
}

export async function setStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void> {
  await db.run("UPDATE users SET stripe_customer_id = ? WHERE id = ?", [stripeCustomerId, userId]);
}

export async function setSubscriptionStatus(userId: string, plan: string, status: string): Promise<void> {
  // One transaction: the plan/status change and the billing-anchor stamp must
  // not be separable, or a crash between them leaves an active subscription
  // with no period to meter usage against.
  await db.transaction(async (tx) => {
    await tx.run("UPDATE users SET plan = ?, subscription_status = ? WHERE id = ?", [plan, status, userId]);

  // Stamp the billing anchor the first time this account becomes active. It
  // is deliberately never overwritten: the monthly scan period is derived by
  // rolling this date forward, so moving it would silently reset someone's
  // usage mid-cycle.
    if (status === "active" || status === "trialing") {
      await tx.run("UPDATE users SET billing_anchor = ? WHERE id = ? AND billing_anchor IS NULL", [
        new Date().toISOString(),
        userId,
      ]);
    }
  });
}

export async function getUserByStripeCustomerId(stripeCustomerId: string): Promise<User | null> {
  const row = await db.get<UserRow>("SELECT * FROM users WHERE stripe_customer_id = ?", [stripeCustomerId]);
  return row ? toUser(row) : null;
}

export async function updatePassword(userId: string, newPassword: string): Promise<void> {
  const passwordHash = await hashPassword(newPassword);
  await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [passwordHash, userId]);
}

const RESET_TOKEN_LIFETIME_MS = 60 * 60 * 1000; // 1 hour

export async function createPasswordResetToken(userId: string): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_TOKEN_LIFETIME_MS).toISOString();
  // Only the hash is stored: a reset token is a password-equivalent credential
  // for the lifetime of its window, so the database must not hold a replayable
  // copy. The raw value is returned to the caller for delivery and then dropped.
  // Plain INSERT, not SQLite's "INSERT OR REPLACE".
  //
  // The primary key is the hash of a freshly generated 32-byte random token,
  // so a conflict is not reachable and OR REPLACE never had anything to
  // replace. Dropping it removes the one SQLite-specific statement in the
  // application without changing behaviour. Superseding a user's older links
  // is done explicitly by invalidatePasswordResetTokens().
  await db.run("INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)", [
    hashToken(token),
    userId,
    expiresAt,
  ]);
  return token;
}

export async function resolvePasswordResetToken(token: string): Promise<{ userId: string } | null> {
  const tokenHash = hashToken(token);
  const row = await db.get<{ user_id: string; expires_at: string }>(
    "SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?",
    [tokenHash]
  );
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await db.run("DELETE FROM password_resets WHERE token_hash = ?", [tokenHash]);
    return null;
  }
  return { userId: row.user_id };
}

export async function consumePasswordResetToken(token: string): Promise<void> {
  await db.run("DELETE FROM password_resets WHERE token_hash = ?", [hashToken(token)]);
}

/**
 * Drops every outstanding reset token for a user. Called once a password has
 * actually changed, so a second, still-valid reset link cannot be used to take
 * the account back afterwards.
 */
export async function invalidatePasswordResetTokens(userId: string): Promise<void> {
  await db.run("DELETE FROM password_resets WHERE user_id = ?", [userId]);
}

/**
 * Removes reset tokens whose window has closed. Expiry is enforced on lookup;
 * this stops spent rows accumulating.
 */
export async function purgeExpiredPasswordResetTokens(now = new Date()): Promise<number> {
  const result = await db.run("DELETE FROM password_resets WHERE expires_at < ?", [now.toISOString()]);
  return result.changes;
}

export async function updateEmail(userId: string, newEmail: string): Promise<User | null> {
  const existing = await db.get("SELECT 1 AS present FROM users WHERE email = ? AND id != ?", [newEmail, userId]);
  if (existing) throw new EmailAlreadyRegisteredError();
  await db.run("UPDATE users SET email = ? WHERE id = ?", [newEmail, userId]);
  return getUserById(userId);
}

/**
 * Deletes an account and everything that hangs off it.
 *
 * Transactional: a partial delete would leave a user row with orphaned
 * projects, or projects whose owner no longer exists, and the previous
 * implementation issued eleven independent statements with no transaction at
 * all. Child rows go first so the foreign keys (now actually enforced — the
 * SQLite PRAGMA was off, and PostgreSQL enforces them natively) stay satisfied
 * at every step.
 *
 * Note this does NOT cancel a Stripe subscription; see cancelSubscription in
 * billing/. Deleting the row here while Stripe keeps billing is exactly the
 * failure the caller must avoid, so the route orders those two operations
 * deliberately.
 */
export async function deleteUser(userId: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.run("DELETE FROM password_resets WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM sessions WHERE user_id = ?", [userId]);

    const projects = await tx.all<{ id: string }>("SELECT id FROM projects WHERE user_id = ?", [userId]);
    for (const project of projects) {
      await tx.run("DELETE FROM alerts WHERE project_id = ?", [project.id]);
      await tx.run("DELETE FROM events WHERE project_id = ?", [project.id]);
      await tx.run("DELETE FROM scans WHERE project_id = ?", [project.id]);
      await tx.run("DELETE FROM finding_statuses WHERE project_id = ?", [project.id]);
    }
    await tx.run("DELETE FROM projects WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM notification_preferences WHERE user_id = ?", [userId]);
    // Metered-usage rows for an account that no longer exists. Nothing
    // reconciles them against anything, and getQuotaState only reads them per
    // live user.
    await tx.run("DELETE FROM scan_usage WHERE user_id = ?", [userId]);
    await tx.run("DELETE FROM users WHERE id = ?", [userId]);
  });
}
