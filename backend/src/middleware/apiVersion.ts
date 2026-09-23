import type { NextFunction, Request, Response } from "express";

/**
 * API versioning (master spec §30), added without touching a single
 * existing route definition.
 *
 * Every route in routes/*.ts hardcodes its full path inline (e.g.
 * `router.get("/api/projects/:id", ...)`), not a relative path mounted
 * under a shared prefix — so introducing `/api/v1/...` as the versioned
 * surface by remounting each router at a second prefix (`app.use("/api/v1",
 * projectsRouter)`) isn't an option without rewriting every route
 * definition in the app, a much larger and riskier change than this round
 * calls for.
 *
 * Instead, a request to `/api/v1/<rest>` is rewritten in place to
 * `/api/<rest>` before it reaches any router. `/api/v1/...` and the
 * original `/api/...` then serve identical responses from the exact same
 * handler, with zero duplication and zero risk of the two surfaces drifting
 * apart. The unversioned path is not deprecated or removed — it keeps
 * working indefinitely, which matters specifically for
 * badge.routes.ts's SVG/JSON badge URLs: those get pasted into customers'
 * own READMEs as long-lived embeds, and must never change or break once
 * published (see api.ts's badgeSvgUrl on the frontend, which deliberately
 * keeps generating the unversioned URL for exactly this reason). The
 * Stripe webhook URL (routes/billing.routes.ts) is equally fixed — it's
 * configured once in the Stripe dashboard — and is likewise unaffected:
 * Stripe only ever calls the unversioned path it was configured with.
 *
 * A future breaking change gets its own prefix (`/api/v2`) and its own set
 * of routers mounted alongside the existing ones — this middleware doesn't
 * need to change for that, since it only ever strips a literal `v1` path
 * segment.
 */
export function apiVersioning(req: Request, res: Response, next: NextFunction) {
  const match = /^\/api\/v1(\/.*)?$/.exec(req.url);
  if (match) {
    req.url = "/api" + (match[1] ?? "");
  }
  res.setHeader("X-API-Version", "v1");
  next();
}
