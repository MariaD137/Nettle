// Structured JSON logging to stdout. This is deliberately the entire
// implementation — App Runner/ECS/Fargate ship container stdout straight
// into CloudWatch Logs with no agent or SDK involved, so a JSON line per
// event is already "CloudWatch-ready" the moment it's actually deployed
// there. Nothing here claims CloudWatch itself is operational; that's true
// only once an actual AWS deployment exists to verify it against.

export type LogLevel = "debug" | "info" | "warn" | "error";

export function log(level: LogLevel, message: string, fields: Record<string, unknown> = {}): void {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...fields,
  };
  const line = JSON.stringify(entry);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

export const logger = {
  debug: (message: string, fields?: Record<string, unknown>) => log("debug", message, fields),
  info: (message: string, fields?: Record<string, unknown>) => log("info", message, fields),
  warn: (message: string, fields?: Record<string, unknown>) => log("warn", message, fields),
  error: (message: string, fields?: Record<string, unknown>) => log("error", message, fields),
};
