import { gunzipSync } from "node:zlib";
import type { ManagementClient } from "auth0";
import { ExportError } from "../errors.js";
import type { RawUser } from "../model/types.js";
import { toRawUser, type Auth0UserRecord } from "./sanitize.js";

const EXPORT_FIELDS = [
  "user_id",
  "email",
  "email_verified",
  "username",
  "name",
  "nickname",
  "given_name",
  "family_name",
  "created_at",
  "updated_at",
  "last_login",
  "logins_count",
  "blocked",
  "identities",
] as const;

const MAX_EXPORT_BYTES = 512 * 1024 * 1024;

function isGzip(body: Buffer): boolean {
  return body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b;
}

export function parseUserExport(body: Buffer): RawUser[] {
  const uncompressed = isGzip(body) ? gunzipSync(body) : body;
  const text = uncompressed.toString("utf8").trim();
  if (!text) return [];
  if (text.startsWith("[")) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      throw new ExportError("user export file is not valid JSON");
    }
    if (!Array.isArray(parsed)) throw new ExportError("user export file is not a JSON array or NDJSON");
    return parsed.flatMap((row) => {
      const user = row && typeof row === "object" ? toRawUser(row as Auth0UserRecord) : undefined;
      return user ? [user] : [];
    });
  }
  const users: RawUser[] = [];
  const lines = text.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]?.trim() ?? "";
    if (!line) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      throw new ExportError(`user export line ${index + 1} is not valid JSON`);
    }
    if (!parsed || typeof parsed !== "object") continue;
    const user = toRawUser(parsed as Auth0UserRecord);
    if (user) users.push(user);
  }
  return users;
}

async function downloadExport(location: string): Promise<Buffer> {
  const response = await fetch(location, { signal: AbortSignal.timeout(120_000) });
  if (!response.ok) {
    throw new ExportError(`user export download failed (${response.status})`);
  }
  const body = Buffer.from(await response.arrayBuffer());
  if (body.length > MAX_EXPORT_BYTES) {
    throw new ExportError("user export file is larger than 512 MB");
  }
  return body;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Bulk user export (POST /api/v2/jobs/users-exports).
 * Omitting connection_id exports every connection, which is what a full
 * access-review snapshot needs. The file is usually gzip-compressed NDJSON.
 */
export async function exportAllUsers(
  client: ManagementClient,
  options: { pollMs: number; maxPolls: number },
): Promise<RawUser[]> {
  const created = await client.jobs.usersExports.create({
    format: "json",
    fields: EXPORT_FIELDS.map((name) => ({ name })),
  });
  let latest = created;
  for (let attempt = 0; attempt < options.maxPolls; attempt += 1) {
    latest = await client.jobs.get(created.id);
    if (latest.status === "completed") break;
    if (latest.status === "failed") {
      const detail = latest.status_details ? `: ${latest.status_details}` : "";
      throw new ExportError(`user export job ${created.id} failed${detail}`);
    }
    await sleep(options.pollMs);
  }
  if (latest.status !== "completed") {
    throw new ExportError(`user export job ${created.id} did not finish after ${options.maxPolls} polls`);
  }
  if (!latest.location) {
    throw new ExportError(`user export job ${created.id} completed without a download location`);
  }
  return parseUserExport(await downloadExport(latest.location));
}
