import express, { type NextFunction, type Request, type Response } from "express";
import { healthRouter } from "./routes/health.routes";
import { scansRouter } from "./routes/scans.routes";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(healthRouter);
app.use(scansRouter);

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error(err);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Nettle backend listening on port ${PORT}`);
});
