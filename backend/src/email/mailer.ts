// Minimal outbound email hook. No provider is wired up yet — until
// SMTP/API credentials are configured, sending is a documented no-op rather
// than a silent one. What this module guarantees either way: a message's
// contents (including a password reset link) are never written to the
// process log — logs are not a secure delivery channel for a single-use
// credential.
export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
}

export async function sendEmail(message: EmailMessage): Promise<boolean> {
  const configured = Boolean(process.env.SMTP_HOST || process.env.EMAIL_PROVIDER_API_KEY);
  if (!configured) {
    console.log(`[email] No provider configured — not sent (to: ${message.to}, subject: "${message.subject}")`);
    return false;
  }
  throw new Error("An email provider is configured but no send implementation exists yet");
}
