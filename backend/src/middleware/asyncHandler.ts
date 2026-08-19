import type { NextFunction, Request, RequestHandler, Response } from "express";

// Express 4 does not catch a rejected promise returned by an async route
// handler — an unhandled DB error would otherwise surface only as an
// unhandledRejection (see index.ts's process-level handler), which alerts
// but never sends the caller a response, leaving the request hanging until
// it times out. Wrapping every handler that awaits a database call in this
// forwards the rejection into next(err), which index.ts's existing 4-arg
// error middleware turns into a proper 500 JSON response. A handler that
// already has its own try/catch covering its whole body is unaffected —
// this only catches what would otherwise escape uncaught.
export function asyncHandler(
  fn: (req: Request, res: Response, next: NextFunction) => Promise<unknown>
): RequestHandler {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
}
