import { db, newId } from "../db";
import type { IncomingEvent, StoredEvent } from "./types";

interface EventRow {
  id: string;
  project_id: string;
  occurred_at: string;
  ip: string;
  method: string;
  path: string;
  status_code: number;
  user_agent: string | null;
}

function toEvent(row: EventRow): StoredEvent {
  return {
    id: row.id,
    projectId: row.project_id,
    occurredAt: row.occurred_at,
    ip: row.ip,
    method: row.method,
    path: row.path,
    statusCode: row.status_code,
    userAgent: row.user_agent ?? undefined,
  };
}

export async function recordEvent(projectId: string, event: IncomingEvent): Promise<StoredEvent> {
  const stored: StoredEvent = {
    id: newId(),
    projectId,
    occurredAt: new Date().toISOString(),
    ...event,
  };
  await db.run(
    "INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [stored.id, stored.projectId, stored.occurredAt, stored.ip, stored.method, stored.path, stored.statusCode, stored.userAgent ?? null]
  );
  return stored;
}

/** Events for this project in the last `windowSeconds`, newest last. */
export async function recentEvents(projectId: string, windowSeconds: number): Promise<StoredEvent[]> {
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const rows = await db.all<EventRow>(
    "SELECT * FROM events WHERE project_id = ? AND occurred_at >= ? ORDER BY occurred_at ASC",
    [projectId, since]
  );
  return rows.map(toEvent);
}
