export interface SendSmsResult {
  sent: boolean;
  sid?: string;
  error?: string;
}

// Talks to Twilio's REST API directly over fetch (same style as the rest of
// this codebase's integrations — see integrations/slack.ts, webhooks.ts —
// rather than pulling in the Twilio SDK). TWILIO_API_BASE is read at call
// time so tests can point it at a local stand-in server shaped like
// Twilio's API without any real account — this exercises the real request
// construction and response handling, but has never been run against
// Twilio's actual production API in this environment (no credentials
// exist here to do so).
export async function sendSms(to: string, body: string): Promise<SendSmsResult> {
  const accountSid = process.env.TWILIO_ACCOUNT_SID;
  const authToken = process.env.TWILIO_AUTH_TOKEN;
  const fromNumber = process.env.TWILIO_FROM_NUMBER;
  if (!accountSid || !authToken || !fromNumber) {
    return { sent: false, error: "SMS is not configured (missing TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN/TWILIO_FROM_NUMBER)" };
  }

  const apiBase = process.env.TWILIO_API_BASE || "https://api.twilio.com";

  try {
    const params = new URLSearchParams({ To: to, From: fromNumber, Body: body });
    const res = await fetch(`${apiBase}/2010-04-01/Accounts/${accountSid}/Messages.json`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });
    const data = await res.json().catch(() => null);

    if (!res.ok) {
      return { sent: false, error: data?.message || `HTTP ${res.status}` };
    }
    return { sent: true, sid: data?.sid };
  } catch (error) {
    return { sent: false, error: error instanceof Error ? error.message : "Unknown error" };
  }
}
