import nodemailer from "nodemailer";

export interface SendEmailResult {
  sent: boolean;
  error?: string;
}

// Transport config is read from env at call time, not cached at module
// load — lets tests point SMTP_HOST/SMTP_PORT at a local receiving server
// per-test without any reset-the-singleton dance, and creating a
// nodemailer transport is cheap (it doesn't open a connection up front).
function buildTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || "localhost",
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || "" } : undefined,
    // Real accounts (Gmail, SES, etc.) require this; a plain local test
    // receiver in CI/dev doesn't speak TLS at all.
    ignoreTLS: process.env.SMTP_SECURE !== "true",
  });
}

export async function sendEmail(to: string, subject: string, text: string, html?: string): Promise<SendEmailResult> {
  try {
    await buildTransport().sendMail({
      from: process.env.SMTP_FROM || "Nettle <alerts@nettle.app>",
      to,
      subject,
      text,
      html,
    });
    return { sent: true };
  } catch (error) {
    console.error("sendEmail failed:", error);
    return { sent: false, error: error instanceof Error ? error.message : "Unknown error" };
  }
}
