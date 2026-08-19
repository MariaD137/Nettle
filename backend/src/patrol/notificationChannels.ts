import { db, newId } from "../db";
import { sendEmail } from "../integrations/email";
import { sendSms } from "../integrations/sms";
import { incrementCounter, Metric } from "../observability/metrics";

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

const DELIVERY_RETRY_BACKOFF_MS = [500, 2000];

async function deliverWithRetry(
  channel: NotificationChannel,
  send: () => Promise<{ sent: boolean; error?: string }>,
  eventType: string
): Promise<void> {
  let lastError: string | undefined;
  let attempt = 0;

  for (; attempt < 1 + DELIVERY_RETRY_BACKOFF_MS.length; attempt++) {
    if (attempt > 0) {
      await new Promise((resolve) => setTimeout(resolve, DELIVERY_RETRY_BACKOFF_MS[attempt - 1]));
    }
    const result = await send();
    if (result.sent) {
      db.prepare(
        "INSERT INTO notification_deliveries (id, project_id, channel, destination, event_type, status, attempt_count, created_at) VALUES (?, ?, ?, ?, ?, 'sent', ?, ?)"
      ).run(newId(), channel.projectId, channel.channel, channel.destination, eventType, attempt + 1, new Date().toISOString());
      return;
    }
    lastError = result.error;
  }

  incrementCounter(Metric.NotificationDeliveryFailures);
  db.prepare(
    "INSERT INTO notification_deliveries (id, project_id, channel, destination, event_type, status, attempt_count, last_error, created_at) VALUES (?, ?, ?, ?, ?, 'failed', ?, ?, ?)"
  ).run(newId(), channel.projectId, channel.channel, channel.destination, eventType, attempt, lastError || null, new Date().toISOString());
  console.error(`Notification channel delivery failed after ${attempt} attempt(s):`, lastError);
}

/**
 * Fans a project event out to every active email/SMS channel subscribed to
 * it. Fire-and-forget from the caller's side — createAlert et al. never
 * await this, so a slow or failing send can't block or fail the request
 * that triggered it — but each delivery gets real retry-with-backoff and
 * its outcome (including which attempt it took, or the final error) is
 * persisted to notification_deliveries, the direct-channel counterpart to
 * webhook_events. `smsBody` should be short (SMS carriers truncate/split
 * long messages); it defaults to `subject` when omitted.
 */
export function notifyChannels(
  projectId: string,
  eventType: string,
  subject: string,
  textBody: string,
  opts?: { html?: string; smsBody?: string }
): void {
  const channels = getNotificationChannels(projectId).filter((c) => c.isActive && c.eventTypes.includes(eventType));

  for (const channel of channels) {
    const send =
      channel.channel === "email"
        ? () => sendEmail(channel.destination, subject, textBody, opts?.html)
        : () => sendSms(channel.destination, opts?.smsBody || subject);
    deliverWithRetry(channel, send, eventType).catch((err) => {
      console.error("Notification delivery threw unexpectedly:", err);
    });
  }
}
