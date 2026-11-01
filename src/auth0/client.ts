import { ManagementClient } from "auth0";
import type { ResolvedConfig } from "../config.js";
import { VERSION } from "../version.js";

export function rewriteManagementUrl(url: string, domain: string, baseUrl: string): string {
  const apiPrefix = `https://${domain}/api/v2`;
  const tokenPrefix = `https://${domain}/oauth/token`;
  const origin = baseUrl.replace(/\/$/, "");
  if (url.startsWith(apiPrefix)) return `${origin}/api/v2${url.slice(apiPrefix.length)}`;
  if (url.startsWith(tokenPrefix)) return `${origin}/oauth/token${url.slice(tokenPrefix.length)}`;
  return url;
}

function requestUrl(input: string | URL | Request): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

/**
 * The official client always calls https://<domain>. A base URL is a test hook
 * (and an escape hatch for a private Management API host): fetch rewrites the
 * token and /api/v2 URLs onto that origin. The client secret is sent there.
 */
export function createRewritingFetch(domain: string, baseUrl: string): typeof fetch {
  return (input, init) => {
    const url = requestUrl(input);
    const rewritten = rewriteManagementUrl(url, domain, baseUrl);
    if (typeof input === "string" || input instanceof URL) return fetch(rewritten, init);
    return fetch(new Request(rewritten, input), init);
  };
}

export function createManagementClient(config: ResolvedConfig): ManagementClient {
  return new ManagementClient({
    domain: config.domain,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    ...(config.audience ? { audience: config.audience } : {}),
    ...(config.baseUrl ? { fetch: createRewritingFetch(config.domain, config.baseUrl) } : {}),
    maxRetries: config.maxRetries,
    telemetry: false,
    clientInfo: { name: "auth0-iga-exporter", version: VERSION },
  });
}
