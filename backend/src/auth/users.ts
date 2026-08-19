import { db, newId } from "../db";
import { hashPassword, verifyPassword } from "./passwords";
import crypto from "crypto";

export interface User {
  id: string;
  email: string;
  plan: string;
  stripeCustomerId: string | null;
  subscriptionStatus: string;
  billingAnchor: string | null;
  onboardingCompletedAt: string | null;
  emailVerifiedAt: string | null;
  isAdmin: boolean;
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
  onboarding_completed_at: string | null;
  email_verified_at: string | null;
  is_admin: number;
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
    onboardingCompletedAt: row.onboarding_completed_at,
    emailVerifiedAt: row.email_verified_at,
    isAdmin: row.is_admin === 1,
    createdAt: row.created_at,
  };
}

// Declarative, restart-to-apply admin grants — there is no API or UI path
// that can make an account an admin. NETTLE_ADMIN_EMAILS is a
// comma-separated allowlist read fresh on every call (startup, and tests
// call it directly), and it's the single source of truth: an email
// removed from the list is actually de-admin'd, not just no-longer-added,
// so access doesn't silently outlive being taken off the list.
export async function syncAdminEmails(): Promise<void> {
  const raw = process.env.NETTLE_ADMIN_EMAILS || "";
  const allowed = new Set(
    raw
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean)
  );

  const rows = (await db.prepare("SELECT id, email, is_admin FROM users").all()) as unknown as {
    id: string;
    email: string;
    is_admin: number;
  }[];

  for (const row of rows) {
    const shouldBeAdmin = allowed.has(row.email.toLowerCase());
    const isAdmin = row.is_admin === 1;
    if (shouldBeAdmin !== isAdmin) {
      await db.prepare("UPDATE users SET is_admin = ? WHERE id = ?").run(shouldBeAdmin ? 1 : 0, row.id);
    }
  }
}

export class EmailAlreadyRegisteredError extends Error {}

export async function createUser(email: string, password: string): Promise<User> {
  const existing = await db.prepare("SELECT 1 FROM users WHERE email = ?").get(email);
  if (existing) throw new EmailAlreadyRegisteredError();

  const passwordHash = await hashPassword(password);
  const id = newId();
  const createdAt = new Date().toISOString();
  await db.prepare("INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)").run(
    id,
    email,
    passwordHash,
    createdAt
  );
  return {
    id,
    email,
    plan: "free",
    stripeCustomerId: null,
    subscriptionStatus: "none",
    billingAnchor: null,
    onboardingCompletedAt: null,
    emailVerifiedAt: null,
    isAdmin: false,
    createdAt,
  };
}

// Used only when no account matches the given email, so verifyCredentials
// below still pays the real scrypt cost either way — otherwise an unknown
// email returns near-instantly while a known one takes the full hash time,
// and that timing difference alone reveals which emails are registered.
// The value itself is arbitrary; it just needs the same salt:hash shape a
// real stored hash has and will never validly match any real password.
const DUMMY_PASSWORD_HASH = `${"a".repeat(32)}:${"b".repeat(128)}`;

export async function verifyCredentials(email: string, password: string): Promise<User | null> {
  const row = (await db.prepare("SELECT * FROM users WHERE email = ?").get(email)) as UserRow | undefined;
  const valid = await verifyPassword(password, row?.password_hash ?? DUMMY_PASSWORD_HASH);
  return row && valid ? toUser(row) : null;
}

export async function getUserById(id: string): Promise<User | null> {
  const row = (await db.prepare("SELECT * FROM users WHERE id = ?").get(id)) as UserRow | undefined;
  return row ? toUser(row) : null;
}

export async function getUserByEmail(email: string): Promise<User | null> {
  const row = (await db.prepare("SELECT * FROM users WHERE email = ?").get(email)) as UserRow | undefined;
  return row ? toUser(row) : null;
}

export async function setStripeCustomerId(userId: string, stripeCustomerId: string): Promise<void> {
  await db.prepare("UPDATE users SET stripe_customer_id = ? WHERE id = ?").run(stripeCustomerId, userId);
}

export async function setSubscriptionStatus(userId: string, plan: string, status: string): Promise<void> {
  await db.prepare("UPDATE users SET plan = ?, subscription_status = ? WHERE id = ?").run(plan, status, userId);

  // Stamp the billing anchor the first time this account becomes active. It
  // is deliberately never overwritten: the monthly scan period is derived by
  // rolling this date forward, so moving it would silently reset someone's
  // usage mid-cycle.
  if (status === "active" || status === "trialing") {
    await db
      .prepare("UPDATE users SET billing_anchor = ? WHERE id = ? AND billing_anchor IS NULL")
      .run(new Date().toISOString(), userId);
  }
}

/**
 * Marks the first-run onboarding flow finished or skipped. Idempotent and
 * never overwritten once set, same as the billing anchor above — a user who
 * revisits an already-completed flow (e.g. a stale tab) shouldn't be able to
 * reset their own completion timestamp.
 */
export async function completeOnboarding(userId: string): Promise<User | null> {
  await db
    .prepare("UPDATE users SET onboarding_completed_at = ? WHERE id = ? AND onboarding_completed_at IS NULL")
    .run(new Date().toISOString(), userId);
  return getUserById(userId);
}

export async function getUserByStripeCustomerId(stripeCustomerId: string): Promise<User | null> {
  const row = (await db.prepare("SELECT * FROM users WHERE stripe_customer_id = ?").get(stripeCustomerId)) as
    | UserRow
    | undefined;
  return row ? toUser(row) : null;
}

export async function updatePassword(userId: string, newPassword: string): Promise<void> {
  const passwordHash = await hashPassword(newPassword);
  await db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(passwordHash, userId);
}

const RESET_TOKEN_LIFETIME_MS = 60 * 60 * 1000; // 1 hour

export async function createPasswordResetToken(userId: string): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + RESET_TOKEN_LIFETIME_MS).toISOString();
  // token is the primary key and freshly random every call, so a real
  // conflict is not expected in practice — the upsert exists to preserve
  // the original INSERT OR REPLACE's replace-on-PK-collision semantics
  // exactly rather than assuming a collision can never happen.
  await db
    .prepare(
      "INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?) " +
        "ON CONFLICT (token) DO UPDATE SET user_id = EXCLUDED.user_id, expires_at = EXCLUDED.expires_at"
    )
    .run(token, userId, expiresAt);
  return token;
}

export async function resolvePasswordResetToken(token: string): Promise<{ userId: string } | null> {
  const row = (await db.prepare("SELECT user_id, expires_at FROM password_resets WHERE token = ?").get(token)) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await db.prepare("DELETE FROM password_resets WHERE token = ?").run(token);
    return null;
  }
  return { userId: row.user_id };
}

export async function consumePasswordResetToken(token: string): Promise<void> {
  await db.prepare("DELETE FROM password_resets WHERE token = ?").run(token);
}

const EMAIL_VERIFICATION_TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours

export async function createEmailVerificationToken(userId: string): Promise<string> {
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + EMAIL_VERIFICATION_TOKEN_LIFETIME_MS).toISOString();
  await db
    .prepare("INSERT INTO email_verifications (token, user_id, expires_at) VALUES (?, ?, ?)")
    .run(token, userId, expiresAt);
  return token;
}

export async function resolveEmailVerificationToken(token: string): Promise<{ userId: string } | null> {
  const row = (await db.prepare("SELECT user_id, expires_at FROM email_verifications WHERE token = ?").get(
    token
  )) as { user_id: string; expires_at: string } | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    await db.prepare("DELETE FROM email_verifications WHERE token = ?").run(token);
    return null;
  }
  return { userId: row.user_id };
}

// Single-use: the token is deleted the moment it's successfully applied,
// same as a password reset token — a link that already worked shouldn't
// keep working if it leaks (email forwarding, browser history, etc).
export async function consumeEmailVerificationToken(token: string): Promise<void> {
  await db.prepare("DELETE FROM email_verifications WHERE token = ?").run(token);
}

export async function markEmailVerified(userId: string): Promise<User | null> {
  await db
    .prepare("UPDATE users SET email_verified_at = ? WHERE id = ? AND email_verified_at IS NULL")
    .run(new Date().toISOString(), userId);
  await db.prepare("DELETE FROM email_verifications WHERE user_id = ?").run(userId);
  return getUserById(userId);
}

export async function updateEmail(userId: string, newEmail: string): Promise<User | null> {
  const existing = await db.prepare("SELECT 1 FROM users WHERE email = ? AND id != ?").get(newEmail, userId);
  if (existing) throw new EmailAlreadyRegisteredError();
  await db.prepare("UPDATE users SET email = ? WHERE id = ?").run(newEmail, userId);
  return getUserById(userId);
}

/**
 * Every table with a project_id/user_id foreign key back to this account
 * gets purged here — this list has drifted behind new feature tables
 * before (webhooks, notification channels, custom rules, api_keys,
 * detection_settings, finding_history, the ml_* tables, scan_usage, and
 * notification_deliveries were all added without ever being added here),
 * leaving orphaned rows — including, for notification_deliveries, a
 * deleted account's real destination email/phone — in the database after
 * "deletion". When adding a new table keyed off project_id or user_id, add
 * its purge here too. (Cross-checked against every CREATE TABLE in
 * db/index.ts as of this comment: the only tables intentionally excluded
 * are `users` itself, deleted last below, and `stripe_events`, which has
 * no user/project ownership at all — it's a global Stripe event-id dedup
 * table, not account data.)
 */
export async function deleteUser(userId: string): Promise<void> {
  await db.prepare("DELETE FROM password_resets WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM email_verifications WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM payment_failures WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM scan_usage WHERE user_id = ?").run(userId);

  const projectIds = (await db.prepare("SELECT id FROM projects WHERE user_id = ?").all(userId)) as unknown as {
    id: string;
  }[];
  for (const p of projectIds) {
    const webhookIds = (await db.prepare("SELECT id FROM webhooks WHERE project_id = ?").all(p.id)) as unknown as {
      id: string;
    }[];
    for (const w of webhookIds) {
      await db.prepare("DELETE FROM webhook_events WHERE webhook_id = ?").run(w.id);
    }
    await db.prepare("DELETE FROM webhooks WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM notification_channels WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM notification_deliveries WHERE project_id = ?").run(p.id);

    const ruleIds = (await db.prepare("SELECT id FROM custom_rules WHERE project_id = ?").all(p.id)) as unknown as {
      id: string;
    }[];
    for (const r of ruleIds) {
      await db.prepare("DELETE FROM rule_versions WHERE rule_id = ?").run(r.id);
      await db.prepare("DELETE FROM rule_test_results WHERE rule_id = ?").run(r.id);
    }
    await db.prepare("DELETE FROM custom_rules WHERE project_id = ?").run(p.id);

    await db.prepare("DELETE FROM api_keys WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM detection_settings WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM finding_history WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM ml_baselines WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM anomaly_scores WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM ml_model_status WHERE project_id = ?").run(p.id);

    await db.prepare("DELETE FROM alerts WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM events WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM scans WHERE project_id = ?").run(p.id);
    await db.prepare("DELETE FROM finding_statuses WHERE project_id = ?").run(p.id);
  }
  await db.prepare("DELETE FROM projects WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM notification_preferences WHERE user_id = ?").run(userId);
  await db.prepare("DELETE FROM users WHERE id = ?").run(userId);
}
