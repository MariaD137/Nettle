/**
 * CORS_ALLOWED_ORIGINS (comma-separated) is the explicit override; falls
 * back to FRONTEND_URL (already used elsewhere for email links) as the
 * single production origin. Returns [] when neither is set — the caller
 * (index.ts) treats that as "reflect whatever origin asks," i.e. local
 * dev's existing wide-open behavior, unchanged.
 */
export function getAllowedOrigins(): string[] {
  return (process.env.CORS_ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}
