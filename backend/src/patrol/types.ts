export interface Project {
  id: string;
  userId: string;
  name: string;
  apiKey: string;
  url: string | null;
  description: string | null;
  environment: string;
  archivedAt: string | null;
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

export type FindingStatus = "open" | "in_progress" | "resolved" | "false_positive" | "accepted_risk";

export interface StoredFindingStatus {
  id: string;
  projectId: string;
  findingHash: string;
  status: FindingStatus;
  notes: string | null;
  createdAt: string;
  updatedAt: string;
}
