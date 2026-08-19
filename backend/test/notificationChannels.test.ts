import { test, before } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "net";
import { SMTPServer } from "smtp-server";
import { createUser } from "../src/auth/users";
import { createProject } from "../src/patrol/projects";
import {
  createNotificationChannel,
  getNotificationChannels,
  updateNotificationChannel,
  deleteNotificationChannel,
  notifyChannels,
  getProjectIdsSubscribedTo,
} from "../src/patrol/notificationChannels";

let projectId: string;
before(async () => {
  const user = await createUser("notification-channels-tests@example.com", "correct horse battery staple");
  projectId = createProject(user.id, "Notification Channels Target").id;
});

test("createNotificationChannel persists and round-trips a channel", () => {
  const channel = createNotificationChannel(projectId, "email", "ops@example.com", ["scan.completed"]);
  assert.equal(channel.projectId, projectId);
  assert.equal(channel.channel, "email");
  assert.equal(channel.destination, "ops@example.com");
  assert.equal(channel.isActive, true);
  assert.deepEqual(channel.eventTypes, ["scan.completed"]);

  const [reloaded] = getNotificationChannels(projectId, "email");
  assert.equal(reloaded.id, channel.id);
});

test("updateNotificationChannel changes destination, event types, and active state independently", () => {
  const channel = createNotificationChannel(projectId, "sms", "+15551234567", ["incident_alert"]);
  const updated = updateNotificationChannel(channel.id, { isActive: false });
  assert.equal(updated!.isActive, false);
  assert.equal(updated!.destination, "+15551234567", "untouched fields are preserved");

  const reactivated = updateNotificationChannel(channel.id, { eventTypes: ["incident_alert", "scan.completed"] });
  assert.deepEqual(reactivated!.eventTypes, ["incident_alert", "scan.completed"]);
});

test("deleteNotificationChannel removes it", () => {
  const channel = createNotificationChannel(projectId, "email", "temp@example.com", ["scan.completed"]);
  deleteNotificationChannel(channel.id);
  assert.ok(!getNotificationChannels(projectId).some((c) => c.id === channel.id));
});

test("getProjectIdsSubscribedTo only returns projects with an active channel for that event type", async () => {
  const user = await createUser("notification-channels-subscribed@example.com", "correct horse battery staple");
  const subscribed = createProject(user.id, "Subscribed").id;
  const unsubscribed = createProject(user.id, "Unsubscribed").id;
  const inactive = createProject(user.id, "Inactive").id;

  createNotificationChannel(subscribed, "email", "a@example.com", ["digest.daily"]);
  createNotificationChannel(unsubscribed, "email", "b@example.com", ["incident_alert"]);
  const inactiveChannel = createNotificationChannel(inactive, "email", "c@example.com", ["digest.daily"]);
  updateNotificationChannel(inactiveChannel.id, { isActive: false });

  const projectIds = getProjectIdsSubscribedTo("digest.daily");
  assert.ok(projectIds.includes(subscribed));
  assert.ok(!projectIds.includes(unsubscribed));
  assert.ok(!projectIds.includes(inactive));
});

test("notifyChannels delivers to a real local mail receiver and a real local SMS stub for a subscribed event, and skips unsubscribed/inactive channels", async () => {
  const user = await createUser("notification-channels-fanout@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Fanout Target").id;

  // Real SMTP receiver.
  const emailReceived: string[] = [];
  const smtp = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, _session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => {
        emailReceived.push(Buffer.concat(chunks).toString("utf8"));
        callback();
      });
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, resolve));
  const smtpPort = (smtp.server.address() as any).port;

  // Real HTTP stub standing in for Twilio.
  const smsReceived: string[] = [];
  const twilioStub = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      smsReceived.push(body);
      res.writeHead(201, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ sid: "SM1" }));
    });
  });
  await new Promise<void>((resolve) => twilioStub.listen(0, resolve));
  const twilioPort = (twilioStub.address() as AddressInfo).port;

  const originalSmtpHost = process.env.SMTP_HOST;
  const originalSmtpPort = process.env.SMTP_PORT;
  const originalTwilioSid = process.env.TWILIO_ACCOUNT_SID;
  const originalTwilioToken = process.env.TWILIO_AUTH_TOKEN;
  const originalTwilioFrom = process.env.TWILIO_FROM_NUMBER;
  const originalTwilioBase = process.env.TWILIO_API_BASE;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(smtpPort);
  process.env.TWILIO_ACCOUNT_SID = "AC_test";
  process.env.TWILIO_AUTH_TOKEN = "tok";
  process.env.TWILIO_FROM_NUMBER = "+15550001111";
  process.env.TWILIO_API_BASE = `http://localhost:${twilioPort}`;

  try {
    createNotificationChannel(project, "email", "ops@example.com", ["scan.completed"]);
    createNotificationChannel(project, "sms", "+15559998888", ["scan.completed"]);
    createNotificationChannel(project, "email", "unsubscribed@example.com", ["incident_alert"]); // different event
    const inactive = createNotificationChannel(project, "email", "paused@example.com", ["scan.completed"]);
    updateNotificationChannel(inactive.id, { isActive: false });

    notifyChannels(project, "scan.completed", "Scan done", "Your scan finished.");

    await new Promise((resolve) => setTimeout(resolve, 400));

    assert.equal(emailReceived.length, 1, "only the one active, subscribed email channel should receive it");
    assert.ok(emailReceived[0].includes("Subject: Scan done"));
    assert.equal(smsReceived.length, 1);
    assert.ok(smsReceived[0].includes("Body=Scan+done") || smsReceived[0].includes("Body=Scan%20done"));
  } finally {
    await new Promise((resolve) => smtp.close(resolve as any));
    twilioStub.close();
    process.env.SMTP_HOST = originalSmtpHost;
    process.env.SMTP_PORT = originalSmtpPort;
    process.env.TWILIO_ACCOUNT_SID = originalTwilioSid;
    process.env.TWILIO_AUTH_TOKEN = originalTwilioToken;
    process.env.TWILIO_FROM_NUMBER = originalTwilioFrom;
    process.env.TWILIO_API_BASE = originalTwilioBase;
  }
});

test("a successful delivery is persisted to notification_deliveries as sent", async () => {
  const user = await createUser("notif-delivery-success@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Delivery Success Target").id;

  const smtp = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, _session, callback) {
      stream.on("data", () => {});
      stream.on("end", callback);
    },
  });
  await new Promise<void>((resolve) => smtp.listen(0, resolve));
  const smtpPort = (smtp.server.address() as AddressInfo).port;
  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(smtpPort);

  try {
    createNotificationChannel(project, "email", "success@example.com", ["scan.completed"]);
    notifyChannels(project, "scan.completed", "Scan done", "Your scan finished.");

    await new Promise((resolve) => setTimeout(resolve, 400));

    const { db } = await import("../src/db/index");
    const row = db
      .prepare("SELECT status, attempt_count FROM notification_deliveries WHERE project_id = ?")
      .get(project) as { status: string; attempt_count: number };
    assert.equal(row.status, "sent");
    assert.equal(row.attempt_count, 1);
  } finally {
    await new Promise((resolve) => smtp.close(resolve as any));
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
  }
});

test("a persistently-failing delivery retries with backoff, then persists status=failed with the real attempt count and error", async () => {
  const user = await createUser("notif-delivery-failure@example.com", "correct horse battery staple");
  const project = createProject(user.id, "Delivery Failure Target").id;

  const originalSid = process.env.TWILIO_ACCOUNT_SID;
  delete process.env.TWILIO_ACCOUNT_SID; // sendSms fails deterministically and immediately every attempt

  try {
    createNotificationChannel(project, "sms", "+15551234567", ["scan.completed"]);
    const before = (await import("../src/observability/metrics")).getMetricsSnapshot().counters[
      "notification_delivery_failures_total"
    ] || 0;

    notifyChannels(project, "scan.completed", "Scan done", "Your scan finished.");

    // 1 initial attempt + backoff of 500ms + 2000ms between the 2 retries.
    await new Promise((resolve) => setTimeout(resolve, 3200));

    const { db } = await import("../src/db/index");
    const row = db
      .prepare("SELECT status, attempt_count, last_error FROM notification_deliveries WHERE project_id = ?")
      .get(project) as { status: string; attempt_count: number; last_error: string };
    assert.equal(row.status, "failed");
    assert.equal(row.attempt_count, 3);
    assert.ok(row.last_error.includes("SMS is not configured"));

    const after = (await import("../src/observability/metrics")).getMetricsSnapshot().counters[
      "notification_delivery_failures_total"
    ] || 0;
    assert.equal(after, before + 1);
  } finally {
    process.env.TWILIO_ACCOUNT_SID = originalSid;
  }
});
