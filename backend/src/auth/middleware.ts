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
