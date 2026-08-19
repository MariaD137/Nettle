import { test } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import type { Server } from "http";
import { AddressInfo } from "net";
import { createUser } from "../src/auth/users";
import { createSession } from "../src/auth/sessions";
import { createProject } from "../src/patrol/projects";
import { updateModelStatus } from "../src/patrol/mlAnalytics";
import analyticsRouter from "../src/routes/analytics.routes";

// Regression coverage for a real bug: GET /api/analytics/:projectId/dashboard
// sent `model_status: null` straight from getModelStatus() (which returns
// null until a model has actually been trained — true for every project by
// default, since nothing trains one automatically). The frontend's
// ModelStatus component read `status.is_active` with no null guard and no
// error boundary above it in the tree, so visiting Analytics on any
// untrained project — i.e. virtually every real project — crashed the
// entire page to a blank white screen. The dedicated /model-status endpoint
// already had a "not trained yet" fallback; /dashboard now gets an
// equivalent one, in the flat shape the frontend actually consumes.

function listen(app: express.Express): Promise<{ server: Server; base: string }> {
  return new Promise((resolve) => {
    const server = app.listen(0, () => {
      resolve({ server, base: `http://localhost:${(server.address() as AddressInfo).port}` });
    });
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());
  app.use("/api/analytics", analyticsRouter);
  return app;
}

test("GET /api/analytics/:projectId/dashboard sends a real fallback model_status for an untrained project, never null", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("analytics-dashboard-untrained@example.com", "correct horse battery staple");
    const token = createSession(user.id);
    const project = createProject(user.id, "Untrained Model Target");

    const res = await fetch(`${base}/api/analytics/${project.id}/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    assert.equal(res.status, 200);
    const body = await res.json();

    assert.notEqual(body.model_status, null);
    assert.equal(body.model_status.is_active, false);
    assert.equal(body.model_status.training_samples, 0);
    assert.equal(body.model_status.trained_at, null);
  } finally {
    server.close();
  }
});

test("GET /api/analytics/:projectId/dashboard reflects a real trained model's status", async () => {
  const app = buildApp();
  const { server, base } = await listen(app);
  try {
    const user = await createUser("analytics-dashboard-trained@example.com", "correct horse battery staple");
    const token = createSession(user.id);
    const project = createProject(user.id, "Trained Model Target");

    updateModelStatus(project.id, "isolation_forest", true, 0.87, 500);

    const res = await fetch(`${base}/api/analytics/${project.id}/dashboard`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = await res.json();

    assert.equal(body.model_status.is_active, true);
    assert.equal(body.model_status.model_type, "isolation_forest");
    assert.equal(body.model_status.training_samples, 500);
    assert.equal(body.model_status.accuracy, 0.87);
  } finally {
    server.close();
  }
});
