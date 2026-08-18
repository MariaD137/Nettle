import { test } from "node:test";
import assert from "node:assert/strict";
import { SMTPServer } from "smtp-server";
import { sendEmail } from "../src/integrations/email";

interface ReceivedMessage {
  envelopeTo: string[];
  raw: string;
}

// No MIME-parsing dependency here — the SMTP session envelope (RCPT TO) and
// a substring check against the raw DATA payload (headers are always plain
// ASCII, and these test bodies are plain ASCII too, so no transfer-encoding
// decoding is needed) are enough to prove a real message went over the wire.
async function startReceiver(): Promise<{ port: number; received: () => ReceivedMessage[]; close: () => Promise<void> }> {
  const received: ReceivedMessage[] = [];
  const server = new SMTPServer({
    disabledCommands: ["AUTH", "STARTTLS"],
    onData(stream, session, callback) {
      const chunks: Buffer[] = [];
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => {
        received.push({ envelopeTo: session.envelope.rcptTo.map((r) => r.address), raw: Buffer.concat(chunks).toString("utf8") });
        callback();
      });
    },
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.server.address() as any).port;
  return {
    port,
    received: () => received,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

test("sendEmail delivers a real message over SMTP to a local receiver", async () => {
  const receiver = await startReceiver();
  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = String(receiver.port);
  try {
    const result = await sendEmail("someone@example.com", "Test subject", "Plain text body", "<p>HTML body</p>");
    assert.equal(result.sent, true);

    assert.equal(receiver.received().length, 1);
    const message = receiver.received()[0];
    assert.deepEqual(message.envelopeTo, ["someone@example.com"]);
    assert.ok(message.raw.includes("Subject: Test subject"));
    assert.ok(message.raw.includes("Plain text body"));
    assert.ok(message.raw.includes("HTML body"));
  } finally {
    await receiver.close();
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
  }
});

test("sendEmail reports failure instead of throwing when the SMTP server is unreachable", async () => {
  const originalHost = process.env.SMTP_HOST;
  const originalPort = process.env.SMTP_PORT;
  process.env.SMTP_HOST = "localhost";
  process.env.SMTP_PORT = "1"; // nothing listens on port 1
  try {
    const result = await sendEmail("someone@example.com", "Subject", "Body");
    assert.equal(result.sent, false);
    assert.ok(result.error);
  } finally {
    process.env.SMTP_HOST = originalHost;
    process.env.SMTP_PORT = originalPort;
  }
});
