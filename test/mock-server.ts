import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { gzipSync } from "node:zlib";
import { CLIENT_ID, CLIENT_SECRET, decoyUser, fictionalTenant, type Fixture } from "./fixture.js";

export interface MockOptions {
  fixture?: Fixture;
  clientId?: string;
  clientSecret?: string;
  /** How many GET /api/v2/users responses return 429 before a real page. */
  rateLimitUserGets?: number;
  /** Drop roles from member payloads so the exporter calls the member-roles endpoint. */
  omitMemberRoles?: boolean;
  /** Users returned by GET /api/v2/users. Defaults to the fixture users. */
  listUsers?: Fixture["users"];
  /** `total` reported by GET /api/v2/users. Defaults to the list length. */
  reportedUserTotal?: number;
  /** Job status polls that stay pending before the job completes. */
  pendingPolls?: number;
  /** When false, GET /api/v2/connections returns 403. */
  allowConnections?: boolean;
}

export interface RecordedRequest {
  method: string;
  path: string;
}

export interface MockHandle {
  baseUrl: string;
  requests: RecordedRequest[];
  tokenRequests: number;
  /** Body of the last POST /api/v2/jobs/users-exports. */
  exportRequest?: unknown;
  close: () => Promise<void>;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function offset<T>(items: T[], url: URL): { slice: T[]; start: number; limit: number; total: number } {
  const limit = Number(url.searchParams.get("per_page") ?? "50");
  const page = Number(url.searchParams.get("page") ?? "0");
  const start = page * limit;
  return { slice: items.slice(start, start + limit), start, limit, total: items.length };
}

function checkpoint<T>(items: T[], url: URL): { slice: T[]; next?: string; total: number } {
  const take = Number(url.searchParams.get("take") ?? "50");
  const from = Number(url.searchParams.get("from") ?? "0");
  const start = Number.isFinite(from) ? from : 0;
  const slice = items.slice(start, start + take);
  const nextIndex = start + slice.length;
  return {
    slice,
    next: nextIndex < items.length ? String(nextIndex) : undefined,
    total: items.length,
  };
}

export function startMock(options: MockOptions = {}): Promise<MockHandle> {
  const fixture = options.fixture ?? fictionalTenant();
  const clientId = options.clientId ?? CLIENT_ID;
  const clientSecret = options.clientSecret ?? CLIENT_SECRET;
  const listUsers = options.listUsers ?? fixture.users;
  const reportedUserTotal = options.reportedUserTotal ?? listUsers.length;
  const pendingPolls = options.pendingPolls ?? 1;
  const allowConnections = options.allowConnections ?? true;
  let rateBudget = options.rateLimitUserGets ?? 0;
  let jobPolls = 0;
  let jobCreated = false;
  const requests: RecordedRequest[] = [];
  const handle: MockHandle = {
    baseUrl: "",
    requests,
    tokenRequests: 0,
    close: async () => undefined,
  };

  const exportBody = gzipSync(Buffer.from(`${fixture.users.map((user) => JSON.stringify(user)).join("\n")}\n`));

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const path = url.pathname;
    requests.push({ method: req.method ?? "GET", path });

    if (req.method === "POST" && path === "/oauth/token") {
      handle.tokenRequests += 1;
      const body = await readBody(req);
      const params = new URLSearchParams(body);
      if (params.get("grant_type") !== "client_credentials" || params.get("client_id") !== clientId || params.get("client_secret") !== clientSecret) {
        sendJson(res, 401, { error: "access_denied", error_description: "Unauthorized" });
        return;
      }
      sendJson(res, 200, { access_token: "mgmt-test-token", token_type: "Bearer", expires_in: 86_400 });
      return;
    }

    if (path.startsWith("/api/v2/") && req.headers.authorization !== "Bearer mgmt-test-token") {
      sendJson(res, 401, { statusCode: 401, error: "Unauthorized", message: "Invalid token" });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/users") {
      if (rateBudget > 0) {
        rateBudget -= 1;
        sendJson(
          res,
          429,
          { statusCode: 429, error: "Too Many Requests", message: "Global limit has been reached" },
          { "retry-after": "1" },
        );
        return;
      }
      const page = offset(listUsers, url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: reportedUserTotal,
        users: page.slice,
      });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/roles") {
      const page = offset(fixture.roles, url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: page.total,
        roles: page.slice,
      });
      return;
    }

    const rolePermissions = path.match(/^\/api\/v2\/roles\/([^/]+)\/permissions$/);
    if (req.method === "GET" && rolePermissions) {
      const roleId = decodeURIComponent(rolePermissions[1] ?? "");
      const page = offset(fixture.rolePermissions[roleId] ?? [], url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: page.total,
        permissions: page.slice,
      });
      return;
    }

    const roleUsers = path.match(/^\/api\/v2\/roles\/([^/]+)\/users$/);
    if (req.method === "GET" && roleUsers) {
      const roleId = decodeURIComponent(roleUsers[1] ?? "");
      const page = checkpoint(fixture.roleUsers[roleId] ?? [], url);
      sendJson(res, 200, { users: page.slice, total: page.total, next: page.next ?? null });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/organizations") {
      const page = checkpoint(fixture.organizations, url);
      sendJson(res, 200, { organizations: page.slice, total: page.total, next: page.next ?? null });
      return;
    }

    const memberRoles = path.match(/^\/api\/v2\/organizations\/([^/]+)\/members\/([^/]+)\/roles$/);
    if (req.method === "GET" && memberRoles) {
      const orgId = decodeURIComponent(memberRoles[1] ?? "");
      const userId = decodeURIComponent(memberRoles[2] ?? "");
      const member = (fixture.members[orgId] ?? []).find((item) => item.user_id === userId);
      const roles = member?.roles ?? [];
      const page = offset(roles, url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: page.total,
        roles: page.slice,
      });
      return;
    }

    const members = path.match(/^\/api\/v2\/organizations\/([^/]+)\/members$/);
    if (req.method === "GET" && members) {
      const orgId = decodeURIComponent(members[1] ?? "");
      const rows = (fixture.members[orgId] ?? []).map((member) => {
        if (!options.omitMemberRoles) return member;
        const rest: Record<string, unknown> = { ...member };
        delete rest.roles;
        return rest;
      });
      const page = checkpoint(rows, url);
      sendJson(res, 200, { members: page.slice, total: page.total, next: page.next ?? null });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/clients") {
      const page = offset(fixture.clients, url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: page.total,
        clients: page.slice,
      });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/resource-servers") {
      const page = offset(fixture.resourceServers, url);
      sendJson(res, 200, {
        start: page.start,
        limit: page.limit,
        length: page.slice.length,
        total: page.total,
        resource_servers: page.slice,
      });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/connections") {
      if (!allowConnections) {
        sendJson(res, 403, { statusCode: 403, error: "Forbidden", message: "Insufficient scope, expected any of: read:connections" });
        return;
      }
      const page = checkpoint(fixture.connections, url);
      sendJson(res, 200, { connections: page.slice, total: page.total, next: page.next ?? null });
      return;
    }

    if (req.method === "POST" && path === "/api/v2/jobs/users-exports") {
      handle.exportRequest = JSON.parse(await readBody(req)) as unknown;
      jobCreated = true;
      sendJson(res, 200, {
        id: "job_fictional_export",
        type: "users_export",
        status: "pending",
        format: "json",
        created_at: "2026-04-30T00:00:00.000Z",
      });
      return;
    }

    if (req.method === "GET" && path === "/api/v2/jobs/job_fictional_export") {
      if (!jobCreated) {
        sendJson(res, 404, { statusCode: 404, error: "Not Found", message: "Job not found" });
        return;
      }
      jobPolls += 1;
      if (jobPolls <= pendingPolls) {
        sendJson(res, 200, {
          id: "job_fictional_export",
          type: "users_export",
          status: "pending",
          percentage_done: 10,
        });
        return;
      }
      sendJson(res, 200, {
        id: "job_fictional_export",
        type: "users_export",
        status: "completed",
        percentage_done: 100,
        location: `${handle.baseUrl}/downloads/users.ndjson.gz`,
      });
      return;
    }

    if (req.method === "GET" && path === "/downloads/users.ndjson.gz") {
      res.writeHead(200, {
        "content-type": "application/gzip",
        "content-length": exportBody.length,
      });
      res.end(exportBody);
      return;
    }

    sendJson(res, 404, { statusCode: 404, error: "Not Found", message: `No mock route for ${req.method} ${path}` });
  });

  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("mock server did not bind a TCP port"));
        return;
      }
      handle.baseUrl = `http://127.0.0.1:${address.port}`;
      handle.close = () =>
        new Promise((closeResolve, closeReject) => {
          server.close((err) => (err ? closeReject(err) : closeResolve()));
        });
      resolve(handle);
    });
  });
}

export function decoyList(): Fixture["users"] {
  return [decoyUser()];
}
