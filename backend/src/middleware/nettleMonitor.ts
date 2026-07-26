import type { NextFunction, Request, Response } from "express";

export interface NettleMonitorOptions {
  apiKey: string;
  /** Defaults to Nettle's hosted ingestion endpoint. Override for local testing. */
  endpoint?: string;
  /** Abort the outgoing report after this long so a slow/unreachable collector never piles up. */
  timeoutMs?: number;
}

const DEFAULT_ENDPOINT = "https://api.nettle.dev/api/events";
const DEFAULT_TIMEOUT_MS = 2000;

/**
 * Express middleware a customer installs once: `app.use(nettleMonitor({ apiKey }))`.
 *
 * This must never be the reason their app slows down or breaks. Reporting is
 * fire-and-forget, wrapped so a network error, a timeout, or Nettle's own
 * ingestion endpoint being down can never throw into the customer's request
 * handling or hold up their response.
 */
export function nettleMonitor(options: NettleMonitorOptions) {
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return function nettleMonitorMiddleware(req: Request, res: Response, next: NextFunction) {
    res.on("finish", () => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);

      fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Nettle-Api-Key": options.apiKey,
        },
        body: JSON.stringify({
          ip: req.ip,
          method: req.method,
          path: req.originalUrl,
          statusCode: res.statusCode,
          userAgent: req.get("user-agent"),
        }),
        signal: controller.signal,
      })
        .catch(() => {
          // Deliberately swallowed. Monitoring must never surface as an
          // error to the app it's monitoring.
        })
        .finally(() => clearTimeout(timeout));
    });

    next();
  };
}
