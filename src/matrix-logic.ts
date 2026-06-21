/**
 * Pure, deterministic logic extracted from http.ts.
 *
 * http.ts has import-time side effects (reads /secrets/config.json and runs the
 * startup()/sync loop at module load), so it cannot be imported in tests. These
 * functions are the side-effect-free pieces — parsing, validation, formatting,
 * buffer capping, sliding-window rate limiting, backoff math — factored out so
 * they can be exercised directly. http.ts re-imports them; behavior is unchanged.
 */

// ── Config normalization & validation ──────────────────────

export interface MatrixConfig {
  homeserver: string;
  userId: string;
  password: string;
  defaultRoomId: string;
}

/**
 * Validate and normalize a parsed config.json object. Trailing slashes are
 * stripped from the homeserver. Throws if any required field is missing/falsy.
 */
export function normalizeConfig(parsed: Record<string, unknown>): MatrixConfig {
  if (!parsed.homeserver || !parsed.userId || !parsed.password || !parsed.defaultRoomId) {
    throw new Error("config.json must contain: homeserver, userId, password, defaultRoomId");
  }

  return {
    homeserver: (parsed.homeserver as string).replace(/\/+$/, ""),
    userId: parsed.userId as string,
    password: parsed.password as string,
    defaultRoomId: parsed.defaultRoomId as string,
  };
}

/**
 * Extract the bare Matrix localpart username from a full user id.
 * "@alice:example.org" → "alice". Tolerates a missing leading "@".
 */
export function extractUsername(userId: string): string {
  return userId.replace(/^@/, "").split(":")[0] ?? "";
}

// ── Reauth backoff ─────────────────────────────────────────

/**
 * Exponential backoff (ms) before the Nth consecutive reauth attempt.
 * First attempt (failures === 0) has no delay; subsequent attempts double from
 * 1000ms and are capped at 8000ms.
 */
export function reauthBackoffMs(consecutiveAuthFailures: number): number {
  if (consecutiveAuthFailures <= 0) return 0;
  return Math.min(1000 * 2 ** (consecutiveAuthFailures - 1), 8000);
}

// ── Login error mapping ────────────────────────────────────

/**
 * Map a Matrix login error body to a human-readable Error message.
 * M_LIMIT_EXCEEDED is surfaced with the rounded-up retry-after in seconds.
 */
export function loginErrorMessage(body: Record<string, unknown>, httpStatus: number): string {
  const errcode = (body.errcode as string) || "UNKNOWN";
  const error = (body.error as string) || `HTTP ${httpStatus}`;
  if (errcode === "M_LIMIT_EXCEEDED") {
    const retryMs = (body.retry_after_ms as number) || 60000;
    return `Rate limited — wait ${Math.ceil(retryMs / 1000)}s before retrying`;
  }
  return `Login failed: ${errcode} — ${error}`;
}

// ── Prompt-injection boundary sanitization ─────────────────

/** Strip sentinel-like patterns from message body to prevent label breakout. */
export function sanitizeBody(body: string): string {
  return body.replace(/---\s*(END\s+)?EXTERNAL\s+USER\s+CONTENT[^-]*---/gi, "[boundary removed]");
}

// ── Reply fallback stripping ───────────────────────────────

/**
 * Strip the Matrix reply fallback that clients prepend to a reply body:
 * leading "> ..." quoted lines plus an optional trailing blank line.
 */
export function stripReplyFallback(body: string): string {
  return body.replace(/^(?:> [^\n]*\n)+\n?/, "");
}

// ── Reply body truncation ──────────────────────────────────

export const MAX_REPLY_BODY_LENGTH = 500;

/** Truncate a reply-context body to MAX_REPLY_BODY_LENGTH, appending "..." if cut. */
export function truncateReplyBody(body: string): string {
  return body.length > MAX_REPLY_BODY_LENGTH ? `${body.slice(0, MAX_REPLY_BODY_LENGTH)}...` : body;
}

// ── Timestamp formatting ───────────────────────────────────

/** Format an epoch-ms timestamp as "YYYY-MM-DD HH:MM:SS" (UTC). */
export function formatTimestamp(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 19);
}

// ── Message buffer ─────────────────────────────────────────

export const MAX_BUFFER_PER_ROOM = 500;
export const MAX_ROOMS = 200;

export interface BufferedMessage {
  eventId: string;
  sender: string;
  body: string;
  timestamp: number;
  roomId: string;
  msgtype?: string;
}

/**
 * Append a message to the per-room buffer, enforcing both caps:
 * - at most MAX_ROOMS distinct rooms (messages for new rooms beyond the cap are dropped)
 * - at most MAX_BUFFER_PER_ROOM messages per room (oldest evicted FIFO)
 * Mutates and returns the same Map. Pure w.r.t. inputs (no I/O, no globals).
 */
export function bufferMessage<T extends BufferedMessage>(
  buffers: Map<string, T[]>,
  msg: T,
): Map<string, T[]> {
  let buffer = buffers.get(msg.roomId);
  if (!buffer) {
    if (buffers.size >= MAX_ROOMS) {
      return buffers; // Drop messages from new rooms once cap reached
    }
    buffer = [];
    buffers.set(msg.roomId, buffer);
  }
  buffer.push(msg);
  if (buffer.length > MAX_BUFFER_PER_ROOM) {
    buffer.splice(0, buffer.length - MAX_BUFFER_PER_ROOM);
  }
  return buffers;
}

export const MAX_PROCESSED_EVENTS = 5000;

/**
 * Track a processed event id, evicting the oldest once MAX_PROCESSED_EVENTS is
 * exceeded (insertion-order eviction, matching Set iteration order).
 * Mutates and returns the same Set.
 */
export function trackEvent(processed: Set<string>, eventId: string): Set<string> {
  processed.add(eventId);
  if (processed.size > MAX_PROCESSED_EVENTS) {
    const first = processed.values().next().value;
    if (first !== undefined) processed.delete(first);
  }
  return processed;
}

// ── Sliding-window rate limiter ────────────────────────────

const RATE_WINDOW_MS = 60_000;

/**
 * Sliding-window rate limit check. Drops timestamps older than `windowMs`,
 * then either records `now` and returns false (allowed), or returns true
 * (limited) when the window is already full. Mutates `timestamps` in place.
 */
export function isRateLimited(
  timestamps: number[],
  now: number,
  limit: number,
  windowMs: number = RATE_WINDOW_MS,
): boolean {
  while (timestamps.length > 0 && (timestamps[0] as number) < now - windowMs) {
    timestamps.shift();
  }
  if (timestamps.length >= limit) return true;
  timestamps.push(now);
  return false;
}

// ── Sync health ────────────────────────────────────────────

/** Overall service health = sync loop running AND a recent successful sync. */
export function isHealthy(syncRunning: boolean, syncHealthy: boolean): boolean {
  return syncRunning && syncHealthy;
}

// ── /media path parsing ────────────────────────────────────

export interface MediaPathResult {
  ok: boolean;
  status?: number;
  error?: string;
  serverName?: string;
  mediaId?: string;
}

/**
 * Parse and validate a "/media/{serverName}/{mediaId}" request path.
 * Enforces the SSRF allowlist (serverName must equal homeserverHost) and
 * rejects path-traversal in mediaId. `pathname` is the full request pathname.
 */
export function parseMediaPath(pathname: string, homeserverHost: string): MediaPathResult {
  const prefix = "/media/";
  const pathAfter = pathname.slice(prefix.length);
  const slashIdx = pathAfter.indexOf("/");
  if (slashIdx < 1) {
    return { ok: false, status: 400, error: "Bad path: /media/{serverName}/{mediaId}" };
  }
  const serverName = pathAfter.slice(0, slashIdx);
  const mediaId = pathAfter.slice(slashIdx + 1);

  if (!serverName || !mediaId) {
    return { ok: false, status: 400, error: "Bad path: /media/{serverName}/{mediaId}" };
  }

  if (serverName !== homeserverHost) {
    return { ok: false, status: 403, error: `Forbidden: serverName must be ${homeserverHost}` };
  }

  if (mediaId.includes("..") || mediaId.includes("/") || mediaId.includes("\\")) {
    return { ok: false, status: 400, error: "Bad mediaId: path traversal rejected" };
  }

  return { ok: true, serverName, mediaId };
}

// ── /messages allowlist parsing & filtering ────────────────

/** Parse a comma-separated allowed_senders param into a trimmed, non-empty Set. */
export function parseAllowedSenders(raw: string): Set<string> {
  return new Set(
    raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );
}

/**
 * Whether a message should be included in the /messages response.
 * Excludes the bot's own echoes; when an allowlist is non-empty, only allowed
 * senders pass.
 */
export function isSenderAllowed(
  sender: string,
  selfUserId: string,
  allowedSenders: Set<string>,
): boolean {
  if (sender === selfUserId) return false;
  if (allowedSenders.size > 0 && !allowedSenders.has(sender)) return false;
  return true;
}
