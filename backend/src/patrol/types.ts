export interface Project {
  id: string;
  userId: string;
  name: string;
  apiKey: string;
  createdAt: string;
}

export interface IncomingEvent {
  ip: string;
  method: string;
  path: string;
  statusCode: number;
  userAgent?: string;
}

export interface StoredEvent extends IncomingEvent {
  id: string;
  projectId: string;
  occurredAt: string;
}

export type AlertSeverity = "critical" | "high" | "medium" | "low";

export type AlertStatus = "new" | "acknowledged" | "resolved" | "false_positive";

export interface Alert {
  id: string;
  projectId: string;
  occurredAt: string;
  severity: AlertSeverity;
  rule: string;
  message: string;
  status: AlertStatus;
}
