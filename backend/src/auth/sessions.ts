import { db, newSessionToken } from "../db";

const SESSION_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export function createSession(userId: string): string {
  const token = newSessionToken();
  const now = new Date();
  db.prepare("INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)").run(
    token,
    userId,
    now.toISOString(),
    new Date(now.getTime() + SESSION_LIFETIME_MS).toISOString()
  );
  return token;
}

export function resolveSession(token: string): { userId: string } | null {
  const row = db.prepare("SELECT user_id, expires_at FROM sessions WHERE token = ?").get(token) as
    | { user_id: string; expires_at: string }
    | undefined;
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
    return null;
  }
  return { userId: row.user_id };
}

export function destroySession(token: string): void {
  db.prepare("DELETE FROM sessions WHERE token = ?").run(token);
}

export interface SessionInfo {
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  current: boolean;
}

export function listSessions(userId: string, currentToken?: string): SessionInfo[] {
  const rows = db.prepare("SELECT token, created_at, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC").all(userId) as unknown as { token: string; created_at: string; expires_at: string }[];
  const now = Date.now();
  return rows
    .filter((r) => new Date(r.expires_at).getTime() > now)
    .map((r) => ({
      tokenPrefix: r.token.slice(0, 8) + "…",
      createdAt: r.created_at,
      expiresAt: r.expires_at,
      current: r.token === currentToken,
    }));
}

export function destroyAllSessions(userId: string): void {
  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
}

export function destroySessionByPrefix(userId: string, tokenPrefix: string): boolean {
  const prefix = tokenPrefix.replace("…", "");
  const rows = db.prepare("SELECT token FROM sessions WHERE user_id = ? AND token LIKE ?").all(userId, `${prefix}%`) as unknown as { token: string }[];
  if (rows.length === 0) return false;
  for (const row of rows) {
    db.prepare("DELETE FROM sessions WHERE token = ?").run(row.token);
  }
  return true;
}
