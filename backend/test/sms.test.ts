import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { AddressInfo } from "net";
import { sendSms } from "../src/integrations/sms";

function startTwilioStub(status: number, body: object): Promise<{ url: string; requests: () => any[]; close: () => Promise<void> }> {
  const requests: any[] = [];
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        requests.push({ method: req.method, url: req.url, headers: req.headers, params: new URLSearchParams(raw) });
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(body));
      });
    });
    server.listen(0, () => {
      const url = `http://localhost:${(server.address() as AddressInfo).port}`;
      resolve({ url, requests: () => requests, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

function applyEnv(vars: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(vars)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> {
  const previous: Record<string, string | undefined> = {};
  for (const key of Object.keys(vars)) previous[key] = process.env[key];
  applyEnv(vars);
  return fn().finally(() => applyEnv(previous));
}

test("sendSms POSTs a correctly-shaped, Basic-authenticated request to Twilio's Messages endpoint", async () => {
  const stub = await startTwilioStub(201, { sid: "SM123", status: "queued" });
  try {
    const result = await withEnv(
      {
        TWILIO_ACCOUNT_SID: "AC_test",
        TWILIO_AUTH_TOKEN: "test_token",
        TWILIO_FROM_NUMBER: "+15550001111",
        TWILIO_API_BASE: stub.url,
      },
      () => sendSms("+15559998888", "Nettle: scan completed")
    );

    assert.equal(result.sent, true);
    assert.equal(result.sid, "SM123");

    const [req] = stub.requests();
    assert.equal(req.method, "POST");
    assert.equal(req.url, "/2010-04-01/Accounts/AC_test/Messages.json");
    assert.equal(req.params.get("To"), "+15559998888");
    assert.equal(req.params.get("From"), "+15550001111");
    assert.equal(req.params.get("Body"), "Nettle: scan completed");
    assert.equal(req.headers.authorization, `Basic ${Buffer.from("AC_test:test_token").toString("base64")}`);
  } finally {
    await stub.close();
  }
});

test("sendSms surfaces Twilio's error body on a non-2xx response instead of throwing", async () => {
  const stub = await startTwilioStub(400, { message: "The 'To' number is not a valid phone number." });
  try {
    const result = await withEnv(
      { TWILIO_ACCOUNT_SID: "AC_test", TWILIO_AUTH_TOKEN: "tok", TWILIO_FROM_NUMBER: "+15550001111", TWILIO_API_BASE: stub.url },
      () => sendSms("not-a-number", "body")
    );
    assert.equal(result.sent, false);
    assert.equal(result.error, "The 'To' number is not a valid phone number.");
  } finally {
    await stub.close();
  }
});

test("sendSms fails cleanly when Twilio credentials are not configured, without making any request", async () => {
  const result = await withEnv(
    { TWILIO_ACCOUNT_SID: undefined, TWILIO_AUTH_TOKEN: undefined, TWILIO_FROM_NUMBER: undefined },
    () => sendSms("+15559998888", "body")
  );
  assert.equal(result.sent, false);
  assert.match(result.error!, /not configured/);
});
