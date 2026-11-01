import { ManagementError } from "auth0";

export function statusOf(err: unknown): number | undefined {
  if (err instanceof ManagementError) return err.statusCode;
  if (err && typeof err === "object" && "statusCode" in err) {
    const status = (err as { statusCode?: unknown }).statusCode;
    return typeof status === "number" ? status : undefined;
  }
  return undefined;
}

export function formatApiError(err: unknown): string {
  if (!(err instanceof ManagementError)) {
    return err instanceof Error ? err.message : String(err);
  }
  let detail = err.message;
  if (err.body && typeof err.body === "object" && "message" in err.body) {
    const message = (err.body as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) detail = message;
  }
  const status = err.statusCode ?? "unknown";
  if (status === 401) {
    return `Management API rejected the machine-to-machine credentials (${status}). Check AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET. ${detail}`;
  }
  if (status === 403) {
    return `Management API refused the call (${status}). A read scope is missing. Run \`auth0-iga-exporter scopes\`. ${detail}`;
  }
  if (status === 429) {
    return `Management API rate limit persisted after retries (${status}). ${detail}`;
  }
  return `Management API request failed (${status}): ${detail}`;
}
