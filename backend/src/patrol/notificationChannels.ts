import { db, newId } from "../db";
import { sendEmail } from "../integrations/email";
import { sendSms } from "../integrations/sms";

export type NotificationChannelType = "email" | "sms";

export interface NotificationChannel {
  id: string;
  projectId: string;
  channel: NotificationChannelType;
  destination: string;
  isActive: boolean;
  eventTypes: string[];
  createdAt: string;
  updatedAt: string;
}

interface ChannelRow {
  id: string;
  project_id: string;
  channel: string;
  destination: string;
  is_active: number;
  event_types: string;
  created_at: string;
  updated_at: string;
}

function toChannel(row: ChannelRow): NotificationChannel {
  return {
    id: row.id,
    projectId: row.project_id,
    channel: row.channel as NotificationChannelType,
    destination: row.destination,
    isActive: row.is_active === 1,
    eventTypes: JSON.parse(row.event_types),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function createNotificationChannel(
  projectId: string,
  channel: NotificationChannelType,
  destination: string,
  eventTypes: string[]
): NotificationChannel {
  const now = new Date().toISOString();
  const row: ChannelRow = {
    id: newId(),
    project_id: projectId,
    channel,
    destination,
    is_active: 1,
    event_types: JSON.stringify(eventTypes),
    created_at: now,
    updated_at: now,
  };
  db.prepare(
    "INSERT INTO notification_channels (id, project_id, channel, destination, is_active, event_types, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(row.id, row.project_id, row.channel, row.destination, row.is_active, row.event_types, row.created_at, row.updated_at);
  return toChannel(row);
}

/** Every project with at least one active channel subscribed to `eventType` — used to know which projects need a digest composed for them, without loading every channel for every project up front. */
export function getProjectIdsSubscribedTo(eventType: string): string[] {
  const rows = db.prepare("SELECT DISTINCT project_id, event_types, is_active FROM notification_channels").all() as unknown as {
    project_id: string;
    event_types: string;
    is_active: number;
  }[];
  const projectIds = new Set<string>();
  for (const row of rows) {
    if (row.is_active === 1 && (JSON.parse(row.event_types) as string[]).includes(eventType)) {
      projectIds.add(row.project_id);
    }
  }
  return [...projectIds];
}

export function getNotificationChannels(projectId: string, channel?: NotificationChannelType): NotificationChannel[] {
  const rows = channel
    ? (db.prepare("SELECT * FROM notification_channels WHERE project_id = ? AND channel = ?").all(projectId, channel) as unknown as ChannelRow[])
    : (db.prepare("SELECT * FROM notification_channels WHERE project_id = ?").all(projectId) as unknown as ChannelRow[]);
  return rows.map(toChannel);
}

export function getNotificationChannel(id: string): NotificationChannel | null {
  const row = db.prepare("SELECT * FROM notification_channels WHERE id = ?").get(id) as ChannelRow | undefined;
  return row ? toChannel(row) : null;
}

export function updateNotificationChannel(
  id: string,
  updates: { destination?: string; eventTypes?: string[]; isActive?: boolean }
): NotificationChannel | null {
  const existing = db.prepare("SELECT * FROM notification_channels WHERE id = ?").get(id) as ChannelRow | undefined;
  if (!existing) return null;

  const now = new Date().toISOString();
  db.prepare(
    "UPDATE notification_channels SET destination = ?, event_types = ?, is_active = ?, updated_at = ? WHERE id = ?"
  ).run(
    updates.destination !== undefined ? updates.destination : existing.destination,
    updates.eventTypes !== undefined ? JSON.stringify(updates.eventTypes) : existing.event_types,
    updates.isActive !== undefined ? (updates.isActive ? 1 : 0) : existing.is_active,
    now,
    id
  );
  return toChannel(db.prepare("SELECT * FROM notification_channels WHERE id = ?").get(id) as unknown as ChannelRow);
}

export function deleteNotificationChannel(id: string): void {
  db.prepare("DELETE FROM notification_channels WHERE id = ?").run(id);
}

/**
 * Fans a project event out to every active email/SMS channel subscribed to
 * it. Fire-and-forget by design, matching notifyAlertWebhooks/
 * notifyScanCompleted — a slow or failing send must never block or fail
 * the caller. `smsBody` should be short (SMS carriers truncate/split long
 * messages); it defaults to `subject` when omitted.
 */
export function notifyChannels(
  projectId: string,
  eventType: string,
  subject: string,
  textBody: string,
  opts?: { html?: string; smsBody?: string }
): void {
  const channels = getNotificationChannels(projectId).filter((c) => c.isActive && c.eventTypes.includes(eventType));

  const deliveries = channels.map((c) => {
    if (c.channel === "email") return sendEmail(c.destination, subject, textBody, opts?.html);
    return sendSms(c.destination, opts?.smsBody || subject);
  });

  Promise.allSettled(deliveries).then((results) => {
    for (const r of results) {
      if (r.status === "fulfilled" && !r.value.sent) console.error("Notification channel delivery failed:", r.value.error);
      if (r.status === "rejected") console.error("Notification channel delivery threw:", r.reason);
    }
  });
}
