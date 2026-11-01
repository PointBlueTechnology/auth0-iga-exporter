import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { test } from "node:test";
import { rewriteManagementUrl } from "../src/auth0/client.ts";
import { parseUserExport } from "../src/auth0/users-export.ts";
import { loadConfig, parseArgv } from "../src/config.ts";
import { ConfigError } from "../src/errors.ts";
import { normalize } from "../src/model/normalize.ts";
import type { RawSnapshot } from "../src/model/types.ts";
import { accountsToCsv, encodeCell, parseCsv } from "../src/output/csv.ts";
import { redact } from "../src/redact.ts";
import { toRawUser } from "../src/auth0/sanitize.ts";

test("redact replaces long secrets and keeps short tokens", () => {
  assert.equal(redact("secret=test-client-secret-value end", ["test-client-secret-value"]), "secret=[redacted] end");
  assert.equal(redact("blocked=true", ["true"]), "blocked=true");
});

test("rewriteManagementUrl sends token and API calls to the base origin", () => {
  const domain = "tenant.example.auth0.test";
  const base = "http://127.0.0.1:4010";
  assert.equal(
    rewriteManagementUrl(`https://${domain}/oauth/token`, domain, base),
    "http://127.0.0.1:4010/oauth/token",
  );
  assert.equal(
    rewriteManagementUrl(`https://${domain}/api/v2/users?page=0`, domain, base),
    "http://127.0.0.1:4010/api/v2/users?page=0",
  );
  assert.equal(rewriteManagementUrl("https://files.example/export.gz", domain, base), "https://files.example/export.gz");
});

test("toRawUser drops identity provider tokens", () => {
  const user = toRawUser({
    user_id: "google-oauth2|samir",
    email: "samir.okonkwo@example.com",
    identities: [
      {
        provider: "google-oauth2",
        connection: "google-oauth2",
        user_id: "samir",
        isSocial: true,
        access_token: "idp-access-token-value",
        refresh_token: "idp-refresh-token-value",
        profileData: { secret: "profile-secret-value" },
      },
    ],
  });
  const encoded = JSON.stringify(user);
  assert.equal(encoded.includes("idp-access-token-value"), false);
  assert.equal(encoded.includes("idp-refresh-token-value"), false);
  assert.equal(encoded.includes("profile-secret-value"), false);
  assert.equal(user?.identities[0]?.provider, "google-oauth2");
});

test("parseUserExport reads gzip NDJSON and a JSON array", () => {
  const line = JSON.stringify({ user_id: "auth0|avery", email: "avery.chen@example.com", blocked: false });
  const gzip = parseUserExport(gzipSync(Buffer.from(`${line}\n`)));
  assert.equal(gzip.length, 1);
  assert.equal(gzip[0]?.userId, "auth0|avery");
  const array = parseUserExport(Buffer.from(JSON.stringify([{ user_id: "auth0|jordan", blocked: "true" }])));
  assert.equal(array[0]?.blocked, true);
});

test("parseUserExport reports the bad line and not the payload", () => {
  assert.throws(() => parseUserExport(Buffer.from("{not-json}\n")), /line 1/);
});

test("csv quoting, formula neutralization, and round trip", () => {
  assert.equal(encodeCell("Chen, Avery"), '"Chen, Avery"');
  assert.equal(encodeCell('say "hi"'), '"say ""hi"""');
  assert.equal(encodeCell("=cmd"), "'=cmd");
  const csv = accountsToCsv([
    {
      accountId: "auth0|avery",
      name: "avery.chen@example.com",
      displayName: "Chen, Avery",
      description: "Sign-in provider auth0, connection Username-Password-Authentication",
      email: "avery.chen@example.com",
      username: "avery.chen",
      idmAccountId: "avery.chen@example.com",
      disabled: false,
      lastLogin: "2026-04-30T15:04:00.000Z",
      privileged: true,
      status: "ACTIVE",
      connection: "Username-Password-Authentication",
      provider: "auth0",
      identities: [{ provider: "auth0", connection: "Username-Password-Authentication", userId: "avery" }],
      createdAt: "2024-01-15T10:00:00.000Z",
      updatedAt: "2026-04-01T12:00:00.000Z",
      loginsCount: 42,
      emailVerified: true,
      givenName: "Avery",
      familyName: "Chen",
    },
  ]);
  const rows = parseCsv(csv);
  assert.equal(rows[1]?.[2], "Chen, Avery");
  assert.equal(rows[1]?.[9], "true");
});

test("normalize marks admin role holders privileged and keeps blocked status", () => {
  const snapshot: RawSnapshot = {
    domain: "tenant.example.auth0.test",
    applicationName: "Auth0 (tenant.example.auth0.test)",
    usersSource: "list",
    collectedAt: "2026-04-30T00:00:00.000Z",
    users: [
      {
        userId: "auth0|avery",
        email: "avery.chen@example.com",
        name: "Avery Chen",
        blocked: false,
        identities: [{ provider: "auth0", connection: "Username-Password-Authentication", userId: "avery" }],
      },
    ],
    roles: [
      {
        id: "rol_billingadmin",
        name: "Billing Admin",
        description: "Manage invoices",
        permissions: [
          { permissionName: "read:invoices", resourceServerIdentifier: "https://invoices.example.com" },
        ],
        userIds: ["auth0|avery", "auth0|missing"],
      },
    ],
    organizations: [],
    applications: [],
    resourceServers: [],
    connections: [],
  };
  const normalized = normalize(snapshot);
  const avery = normalized.accounts.find((account) => account.accountId === "auth0|avery");
  const missing = normalized.accounts.find((account) => account.accountId === "auth0|missing");
  assert.equal(avery?.privileged, true);
  assert.equal(avery?.status, "ACTIVE");
  assert.equal(missing?.privileged, true);
  assert.match(missing?.description ?? "", /not returned/);
  assert.equal(
    normalized.hierarchy.some((link) => link.relation === "GRANTS" && link.parentPermissionId === "role:rol_billingadmin"),
    true,
  );
});

test("normalize keeps only role-granted Management API scopes unless asked for all", () => {
  const management = "https://tenant.example.auth0.test/api/v2/";
  const snapshot: RawSnapshot = {
    domain: "tenant.example.auth0.test",
    applicationName: "Auth0 (tenant.example.auth0.test)",
    usersSource: "list",
    collectedAt: "2026-04-30T00:00:00.000Z",
    users: [
      { userId: "auth0|avery", email: "avery.chen@example.com", blocked: false, identities: [] },
      { userId: "auth0|nomail", blocked: false, identities: [] },
    ],
    roles: [
      {
        id: "rol_support",
        name: "Support",
        description: "",
        permissions: [{ permissionName: "read:users", resourceServerIdentifier: management }],
        userIds: [],
      },
    ],
    organizations: [],
    applications: [],
    resourceServers: [
      {
        id: "rs_management",
        name: "Auth0 Management API",
        identifier: management,
        isSystem: true,
        scopes: [
          { value: "read:users", description: "Read Users" },
          { value: "delete:users", description: "Delete Users" },
        ],
      },
      {
        id: "rs_invoices",
        name: "Invoices API",
        identifier: "https://invoices.example.com",
        isSystem: false,
        scopes: [{ value: "read:invoices", description: "Read invoices" }],
      },
    ],
    connections: [],
  };
  const scopes = (options?: { includeSystemScopes?: boolean }) =>
    normalize(snapshot, options)
      .permissions.filter((permission) => permission.type === "API_SCOPE")
      .map((permission) => permission.permissionId);

  assert.deepEqual(scopes(), [
    "scope:https://invoices.example.com::read:invoices",
    `scope:${management}::read:users`,
  ]);
  assert.equal(scopes({ includeSystemScopes: true }).includes(`scope:${management}::delete:users`), true);

  const normalized = normalize(snapshot);
  assert.equal(
    normalized.hierarchy.some(
      (link) => link.parentPermissionId === `api:${management}` && link.childPermissionId === `scope:${management}::read:users`,
    ),
    true,
  );
  const verified = Object.fromEntries(normalized.accounts.map((account) => [account.accountId, account.emailVerified]));
  assert.deepEqual(verified, { "auth0|avery": false, "auth0|nomail": null });
});

test("a group mapped to a privileged role is privileged whatever its name", () => {
  const snapshot: RawSnapshot = {
    domain: "tenant.example.auth0.test",
    applicationName: "Auth0 (tenant.example.auth0.test)",
    usersSource: "list",
    collectedAt: "2026-04-30T00:00:00.000Z",
    users: [
      {
        userId: "samlp|okta-workforce|riley",
        blocked: false,
        identities: [{ provider: "samlp", connection: "okta-workforce", userId: "riley" }],
        groups: [{ attribute: "groups", value: "Finance" }],
      },
      {
        userId: "samlp|azure|kai",
        blocked: false,
        identities: [{ provider: "samlp", connection: "azure", userId: "kai" }],
        groups: [{ attribute: "groups", value: "Finance" }],
      },
    ],
    roles: [{ id: "rol_billingadmin", name: "Billing Admin", description: "", permissions: [], userIds: [] }],
    organizations: [],
    applications: [],
    resourceServers: [],
    connections: [],
  };
  const normalized = normalize(snapshot, {
    groupRoleMap: [{ connection: "okta-workforce", group: "Finance", role: "Billing Admin" }],
  });
  const privileged = Object.fromEntries(normalized.accounts.map((account) => [account.accountId, account.privileged]));
  assert.deepEqual(privileged, { "samlp|azure|kai": false, "samlp|okta-workforce|riley": true });
  assert.deepEqual(normalized.unmatchedMappings, []);
  assert.equal(normalized.permissions.filter((permission) => permission.type === "GROUP").length, 2);
});

test("config requires a bare domain and prefers the environment over a file", async () => {
  await assert.rejects(
    () => loadConfig({}, { AUTH0_DOMAIN: "https://tenant.example.auth0.com" }),
    (err: unknown) => err instanceof ConfigError && /bare hostname/.test(err.message),
  );
  const config = await loadConfig(
    { out: "from-flag", perPage: 10 },
    {
      AUTH0_DOMAIN: "tenant.example.auth0.test",
      AUTH0_CLIENT_ID: "from-env",
      AUTH0_CLIENT_SECRET: "env-secret-value",
    },
  );
  assert.equal(config.domain, "tenant.example.auth0.test");
  assert.equal(config.clientId, "from-env");
  assert.equal(config.out, "from-flag");
  assert.equal(config.perPage, 10);
  assert.equal(config.includeSystemScopes, false);
  const parsed = parseArgv(["export", "--include-system-scopes"]);
  assert.equal(parsed.kind === "export" && parsed.flags.includeSystemScopes, true);
  const fromEnv = await loadConfig(
    {},
    {
      AUTH0_DOMAIN: "tenant.example.auth0.test",
      AUTH0_CLIENT_ID: "from-env",
      AUTH0_CLIENT_SECRET: "env-secret-value",
      AUTH0_INCLUDE_SYSTEM_SCOPES: "true",
    },
  );
  assert.equal(fromEnv.includeSystemScopes, true);
  assert.deepEqual(parseArgv(["scopes"]), { kind: "scopes" });
  assert.equal(parseArgv(["--help"]).kind, "help");
  assert.throws(() => parseArgv(["export", "--per-page", "0"]), ConfigError);
});
