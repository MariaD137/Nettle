import dns from "dns";
import net from "net";
import http, { type IncomingMessage } from "http";
import https from "https";
import type { TLSSocket, PeerCertificate } from "tls";

/**
 * A minimal, SSRF-hardened HTTP(S) client for scanning URLs the operator
 * doesn't control. This is the one place in the codebase that makes
 * outbound requests to arbitrary, user-supplied hosts — every check here
 * exists because "fetch a URL the customer typed in" is the textbook SSRF
 * entry point (cloud metadata endpoints, internal admin panels, etc.).
 *
 * Defense in depth, in order:
 *  1. Only http/https schemes are accepted at all.
 *  2. The hostname is resolved via DNS ourselves, and every resolved
 *     address is checked against the private/reserved-range blocklist
 *     before we connect anywhere.
 *  3. The connection is pinned to that validated address (via a custom
 *     `lookup` on the request) rather than left to resolve again at
 *     connect time — this is what actually closes the DNS-rebinding gap
 *     (an attacker's DNS server returning a safe IP to our validation
 *     lookup and a private IP a few seconds later to the real connect).
 *  4. Redirects are followed manually, capped, and each target is run
 *     back through the same validation before being followed — a public
 *     URL redirecting to an internal one is a well-known SSRF bypass.
 *  5. Both a per-request timeout and a total response-size cap are
 *     enforced so a malicious or just slow target can't tie up a worker
 *     indefinitely or exhaust memory.
 *
 * Known limitation, stated plainly rather than silently assumed away:
 * this validates the specific address it connects to, but does not
 * attempt to defeat every conceivable network-level SSRF technique (e.g.
 * a target that behaves differently depending on which of several
 * DNS-returned addresses happens to be picked isn't fully covered beyond
 * "every address returned is validated"). It is a real, meaningful
 * barrier, not a formal proof.
 */

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2MB — plenty for headers/HTML, not for abuse

function ipv4ToLong(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inV4Range(ip: string, base: string, maskBits: number): boolean {
  if (net.isIPv4(ip) === false) return false;
  const mask = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(base) & mask);
}

// RFC 1918 / RFC 3927 / RFC 6598 / loopback / "this network" / multicast /
// reserved, plus the cloud-metadata address specifically (169.254.169.254
// falls under link-local anyway, called out here because it's the single
// highest-value SSRF target there is).
const BLOCKED_V4_RANGES: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, includes 169.254.169.254 metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved
  ["255.255.255.255", 32],
];

function isBlockedIpv4(ip: string): boolean {
  return BLOCKED_V4_RANGES.some(([base, bits]) => inV4Range(ip, base, bits));
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  // IPv4-mapped (::ffff:a.b.c.d) — validate the embedded v4 address too.
  const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIpv4(mapped[1]);
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7 unique local
  if (lower.startsWith("fe8") || lower.startsWith("fe9") || lower.startsWith("fea") || lower.startsWith("feb")) return true; // fe80::/10 link-local
  return false;
}

export function isBlockedIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isBlockedIpv4(ip);
  if (net.isIPv6(ip)) return isBlockedIpv6(ip);
  return true; // not a recognizable IP at all — refuse rather than guess
}

const BLOCKED_HOSTNAMES = new Set(["localhost", "localhost.localdomain", "metadata.google.internal"]);

/**
 * Resolves a hostname and validates every address it comes back with.
 * Returns the first validated address to pin the connection to, and its
 * family (4/6) for the socket options.
 */
async function resolveAndValidate(hostname: string): Promise<{ address: string; family: 4 | 6 }> {
  if (BLOCKED_HOSTNAMES.has(hostname.toLowerCase())) {
    throw new SsrfBlockedError(`Refusing to scan "${hostname}" — reserved hostname`);
  }

  // A literal IP in the URL skips DNS entirely.
  if (net.isIP(hostname)) {
    if (isBlockedIp(hostname)) {
      throw new SsrfBlockedError(`Refusing to scan ${hostname} — private/reserved IP range`);
    }
    return { address: hostname, family: net.isIPv6(hostname) ? 6 : 4 };
  }

  let records: dns.LookupAddress[];
  try {
    records = await dns.promises.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new SsrfBlockedError(`Couldn't resolve "${hostname}": ${(err as Error).message}`);
  }

  if (records.length === 0) {
    throw new SsrfBlockedError(`"${hostname}" did not resolve to any address`);
  }

  for (const r of records) {
    if (isBlockedIp(r.address)) {
      throw new SsrfBlockedError(`Refusing to scan "${hostname}" — resolves to a private/reserved address (${r.address})`);
    }
  }

  return { address: records[0].address, family: records[0].family === 6 ? 6 : 4 };
}

export interface SafeFetchResult {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  finalUrl: string;
  redirectChain: string[];
  tls: { authorized: boolean; protocol: string | null; validTo: string | null; error: string | null } | null;
}

/**
 * The one function everything else in this module should call. Validates
 * the URL, performs the request with the connection pinned to the
 * validated address, follows redirects (re-validating each hop), and
 * enforces size/time limits.
 */
/**
 * Performs the actual GET against a pre-validated (address, family) pair.
 * Split out from ssrfSafeFetch so it can be exercised directly in tests
 * against a local server without needing a bypass flag in the real SSRF
 * gate — resolveAndValidate above is what actually enforces safety, and
 * it's tested separately (see ssrfSafeFetch.test.ts).
 */
export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export async function performValidatedRequest(
  url: URL,
  address: string,
  family: 4 | 6,
  options: RequestOptions = {}
): Promise<{ res: IncomingMessage; body: string }> {
  const isHttps = url.protocol === "https:";
  const client = isHttps ? https : http;
  const method = options.method ?? "GET";

  return new Promise<{ res: IncomingMessage; body: string }>((resolve, reject) => {
    const req = client.request(
      {
        // Connect to the pre-validated IP directly; keep the original
        // hostname for the Host header / TLS SNI so virtual hosting and
        // certificate validation both still work correctly.
        host: address,
        family,
        servername: isHttps ? url.hostname : undefined,
        setHost: false,
        headers: { Host: url.hostname, ...options.headers },
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method,
        timeout: REQUEST_TIMEOUT_MS,
        // Custom lookup pins DNS to the address we already validated,
        // so nothing re-resolves (and potentially rebinds) after the fact.
        lookup: (_hostname, _opts, cb) => cb(null, address, family),
      },
      (res) => {
        let received = 0;
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => {
          received += chunk.length;
          if (received > MAX_RESPONSE_BYTES) {
            res.destroy();
            reject(new Error(`Response exceeded ${MAX_RESPONSE_BYTES} byte limit`));
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve({ res, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      }
    );

    req.on("timeout", () => {
      req.destroy(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.on("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function extractTls(res: IncomingMessage, isHttps: boolean): SafeFetchResult["tls"] {
  if (!isHttps) return null;
  const socket = res.socket as TLSSocket;
  let cert: PeerCertificate | null = null;
  try {
    cert = socket.getPeerCertificate?.() ?? null;
  } catch {
    cert = null;
  }
  return {
    authorized: socket.authorized ?? false,
    protocol: socket.getProtocol?.() ?? null,
    validTo: cert && cert.valid_to ? cert.valid_to : null,
    error: socket.authorizationError ? String(socket.authorizationError) : null,
  };
}

/**
 * The one function everything else in this module should call. Validates
 * the URL, performs the request with the connection pinned to the
 * validated address, follows redirects (re-validating each hop through
 * the exact same gate, since this just calls itself), and enforces
 * size/time limits.
 *
 * `options` defaults to a plain GET (the URL-scanner's use case). Passing
 * `{ method: "POST", headers, body }` is what makes this safe to reuse for
 * outbound webhook delivery too — same DNS-rebinding-safe resolution,
 * same redirect re-validation, same timeout/size caps, just a different
 * HTTP method and a request body.
 */
export async function ssrfSafeFetch(
  targetUrl: string,
  redirectsLeft = MAX_REDIRECTS,
  chainSoFar: string[] = [],
  options: RequestOptions = {}
): Promise<SafeFetchResult> {
  const url = new URL(targetUrl);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfBlockedError(`Unsupported protocol "${url.protocol}" — only http/https are allowed`);
  }

  const { address, family } = await resolveAndValidate(url.hostname);
  const isHttps = url.protocol === "https:";

  const { res, body } = await performValidatedRequest(url, address, family, options);
  const statusCode = res.statusCode ?? 0;
  const tls = extractTls(res, isHttps);

  if (statusCode >= 300 && statusCode < 400 && res.headers.location && redirectsLeft > 0) {
    const nextUrl = new URL(res.headers.location, url).toString();
    return ssrfSafeFetch(nextUrl, redirectsLeft - 1, [...chainSoFar, url.toString()], options);
  }
  if (statusCode >= 300 && statusCode < 400 && redirectsLeft <= 0) {
    throw new SsrfBlockedError(`Too many redirects while fetching ${targetUrl}`);
  }

  return {
    statusCode,
    headers: res.headers as Record<string, string | string[] | undefined>,
    body,
    finalUrl: url.toString(),
    redirectChain: chainSoFar,
    tls,
  };
}
