import type { NextFunction, Request, Response } from "express";
import { resolveSession } from "./sessions";
import { getUserById } from "./users";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      userId?: string;
      userPlan?: string;
    }
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
  if (!token) {
    return res.status(401).json({ error: "Missing Authorization: Bearer <token> header" });
  }
  const session = resolveSession(token);
  if (!session) {
    return res.status(401).json({ error: "Invalid or expired session" });
  }
  req.userId = session.userId;
  const user = getUserById(session.userId);
  if (user) req.userPlan = user.plan;
  next();
}

/**
 * Populates req.userId/req.userPlan when a valid token is present, but lets
 * anonymous callers through. Used by routes that work logged-out yet still
 * need to know the caller's plan — a one-off scan is free to run, but how
 * much of the report comes back depends on who's asking.
 */
export function optionalAuth(req: Request, _res: Response, next: NextFunction) {
  const header = req.header("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length) : null;
  if (token) {
    const session = resolveSession(token);
    if (session) {
      req.userId = session.userId;
      const user = getUserById(session.userId);
      if (user) req.userPlan = user.plan;
    }
  }
  next();
}
