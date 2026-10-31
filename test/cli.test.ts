import assert from "node:assert/strict";
import { writeFile, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { parseCsv } from "../src/output/csv.ts";
import {
  APPLICATION_NAME,
  CLIENT_ID,
  CLIENT_SECRET,
  DECOY_EMAIL,
  SECRET_CLIENT,
  SECRET_CONNECTION,
  SECRET_IDP_ACCESS,
  SECRET_IDP_REFRESH,
  SECRET_SIGNING,
  TENANT_DOMAIN,
} from "./fixture.ts";
import { credentialEnv, childEnv, runCli, tempDir } from "./helpers.ts";
import { decoyList, startMock, type MockHandle } from "./mock-server.ts";

const SECRETS = [CLIENT_SECRET, SECRET_CLIENT, SECRET_SIGNING, SECRET_CONNECTION, SECRET_IDP_ACCESS, SECRET_IDP_REFRESH];

function assertNoSecrets(text: string): void {
  for (const secret of SECRETS) assert.equal(text.includes(secret), false, `output contained a secret value`);
}

async function readOutputs(dir: string): Promise<string> {
  const names = [
    "accounts.csv",
    "permissions.csv",
    "assignments.csv",
    "permission-hierarchy.csv",
    "auth0-iga.json",
    "scim-users.json",
    "scim-groups.json",
    "manifest.json",
  ];
  const chunks = [];
  for (const name of names) chunks.push(await readFile(join(dir, name), "utf8"));
  return chunks.join("\n");
}

test("CLI export against the mock Management API", { timeout: 30_000 }, async () => {
  const mock: MockHandle = await startMock();
  const out = await tempDir();
  try {
    const result = await runCli(
      [
        "export",
        "--out",
        out.dir,
        "--format",
        "all",
        "--users-source",
        "list",
        "--per-page",
        "1",
        "--application-name",
        APPLICATION_NAME,
      ],
      credentialEnv(mock.baseUrl),
    );
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /exported 3 accounts/);
    assert.match(result.stdout, /\(list\)/);
    assertNoSecrets(result.stdout);
    assertNoSecrets(result.stderr);
    assert.equal(mock.tokenRequests, 1);
    assert.equal(
      mock.requests.some((request) => request.path === "/api/v2/jobs/users-exports"),
      false,
    );

    const combined = await readOutputs(out.dir);
    assertNoSecrets(combined);

    const accounts = parseCsv(await readFile(join(out.dir, "accounts.csv"), "utf8"));
    const header = accounts[0];
    assert.equal(header?.[0], "accountId");
    const byId = new Map(accounts.slice(1).map((row) => [row[0], row]));
    const avery = byId.get("auth0|avery");
    assert.ok(avery);
    assert.equal(avery[1], "avery.chen@example.com");
    assert.equal(avery[2], "Chen, Avery");
    assert.equal(avery[7], "false");
    assert.equal(avery[8], "2026-04-30T15:04:00.000Z");
    assert.equal(avery[9], "true");
    assert.equal(avery[10], "ACTIVE");
    assert.equal(avery[11], "Username-Password-Authentication");
    const jordan = byId.get("auth0|jordan");
    assert.equal(jordan?.[7], "true");
    assert.equal(jordan?.[9], "false");
    assert.equal(jordan?.[10], "BLOCKED");
    const samir = byId.get("google-oauth2|samir");
    assert.equal(samir?.[8], "");
    assert.equal(samir?.[12], "google-oauth2");
    assert.equal(JSON.parse(samir?.[13] ?? "[]")[0].provider, "google-oauth2");

    const assignments = parseCsv(await readFile(join(out.dir, "assignments.csv"), "utf8"));
    const pairs = assignments.slice(1).map((row) => row.join("|"));
    assert.ok(pairs.includes("auth0|avery|role:rol_billingadmin|DIRECT_ROLE"));
    assert.ok(pairs.includes("auth0|avery|organization:org_northwind|ORGANIZATION_MEMBER"));
    assert.ok(pairs.includes("auth0|avery|organization-role:org_northwind:rol_viewer|ORGANIZATION_ROLE"));
    assert.ok(pairs.includes("auth0|jordan|role:rol_viewer|DIRECT_ROLE"));
    assert.ok(pairs.includes("google-oauth2|samir|organization:org_northwind|ORGANIZATION_MEMBER"));

    const hierarchy = parseCsv(await readFile(join(out.dir, "permission-hierarchy.csv"), "utf8"));
    const links = hierarchy.slice(1).map((row) => row.join("|"));
    assert.ok(links.includes("role:rol_billingadmin|scope:https://invoices.example.com::write:invoices|GRANTS"));
    assert.ok(
      links.includes("organization:org_northwind|organization-role:org_northwind:rol_viewer|CONTAINS"),
    );
    assert.ok(
      links.includes(
        "organization-role:org_northwind:rol_viewer|scope:https://invoices.example.com::read:invoices|GRANTS",
      ),
    );
    assert.ok(links.includes("api:https://invoices.example.com|scope:https://invoices.example.com::read:invoices|CONTAINS"));

    const permissions = parseCsv(await readFile(join(out.dir, "permissions.csv"), "utf8"));
    assert.ok(permissions.some((row) => row[3] === "APPLICATION" && row[1] === "Northwind Portal"));
    assert.ok(permissions.some((row) => row[3] === "API" && row[4] === "https://directory.example.com"));

    const bundle = JSON.parse(await readFile(join(out.dir, "auth0-iga.json"), "utf8")) as {
      schema: string;
      meta: { usersSource: string; applicationName: string };
      catalog: { connections: Array<{ id: string }>; applications: Array<{ clientId: string }> };
    };
    assert.equal(bundle.schema, "pointblue.auth0-iga-exporter/v0.1");
    assert.equal(bundle.meta.usersSource, "list");
    assert.equal(bundle.meta.applicationName, APPLICATION_NAME);
    assert.deepEqual(
      bundle.catalog.connections.map((connection) => connection.id).sort(),
      ["con_DbUsers00000001", "con_Google000000001"],
    );
    assert.equal(bundle.catalog.applications.some((app) => app.clientId === "spaNorthwindPortal"), true);

    const scimUsers = JSON.parse(await readFile(join(out.dir, "scim-users.json"), "utf8")) as {
      schemas: string[];
      totalResults: number;
      Resources: Array<{ id: string; active: boolean; userName: string }>;
    };
    assert.equal(scimUsers.schemas[0], "urn:ietf:params:scim:api:messages:2.0:ListResponse");
    assert.equal(scimUsers.totalResults, 3);
    assert.equal(scimUsers.Resources.find((user) => user.id === "auth0|jordan")?.active, false);
    const scimGroups = JSON.parse(await readFile(join(out.dir, "scim-groups.json"), "utf8")) as {
      Resources: Array<{ id: string; displayName: string; members: Array<{ value: string }> }>;
    };
    const billing = scimGroups.Resources.find((group) => group.id === "role:rol_billingadmin");
    assert.deepEqual(billing?.members.map((member) => member.value), ["auth0|avery"]);
    const contoso = scimGroups.Resources.find((group) => group.displayName === "Contoso Ltd");
    assert.deepEqual(contoso?.members, []);

    const accountStat = await stat(join(out.dir, "accounts.csv"));
    assert.equal(accountStat.mode & 0o777, 0o600);

    const userPages = mock.requests.filter((request) => request.path === "/api/v2/users");
    assert.ok(userPages.length >= 3, "expected user pagination");
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("429 on the user list is retried", { timeout: 30_000 }, async () => {
  const mock = await startMock({ rateLimitUserGets: 1 });
  const out = await tempDir();
  try {
    const result = await runCli(
      ["export", "--out", out.dir, "--format", "csv", "--users-source", "list"],
      credentialEnv(mock.baseUrl),
    );
    assert.equal(result.code, 0, result.stderr);
    assertNoSecrets(result.stderr);
    const userGets = mock.requests.filter((request) => request.method === "GET" && request.path === "/api/v2/users");
    assert.ok(userGets.length >= 2);
    const accounts = parseCsv(await readFile(join(out.dir, "accounts.csv"), "utf8"));
    assert.equal(accounts.length, 4);
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("auto mode uses the bulk export job when the tenant is at the threshold", { timeout: 30_000 }, async () => {
  const mock = await startMock({ listUsers: decoyList(), reportedUserTotal: 3 });
  const out = await tempDir();
  try {
    const result = await runCli(
      ["export", "--out", out.dir, "--format", "json", "--users-source", "auto", "--export-threshold", "3", "--job-poll-ms", "10"],
      credentialEnv(mock.baseUrl),
    );
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /\(export\)/);
    const bundle = JSON.parse(await readFile(join(out.dir, "auth0-iga.json"), "utf8")) as {
      accounts: Array<{ email: string }>;
    };
    assert.equal(bundle.accounts.some((account) => account.email === "avery.chen@example.com"), true);
    assert.equal(bundle.accounts.some((account) => account.email === DECOY_EMAIL), false);
    assert.equal(mock.requests.some((request) => request.path === "/api/v2/jobs/users-exports"), true);
    assertNoSecrets(JSON.stringify(bundle));
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("export mode downloads gzip NDJSON and organization roles are loaded separately", { timeout: 30_000 }, async () => {
  const mock = await startMock({ omitMemberRoles: true, listUsers: decoyList() });
  const out = await tempDir();
  try {
    const result = await runCli(
      ["export", "--out", out.dir, "--format", "csv", "--users-source", "export", "--job-poll-ms", "10"],
      credentialEnv(mock.baseUrl),
    );
    assert.equal(result.code, 0, result.stderr);
    const assignments = parseCsv(await readFile(join(out.dir, "assignments.csv"), "utf8"));
    const pairs = assignments.slice(1).map((row) => row.join("|"));
    assert.ok(pairs.includes("auth0|avery|organization-role:org_northwind:rol_viewer|ORGANIZATION_ROLE"));
    assert.equal(pairs.some((pair) => pair.includes("auth0|decoy")), false);
    assert.equal(
      mock.requests.some((request) => /\/members\/auth0(?:%7C|\|)avery\/roles/.test(request.path)),
      true,
    );
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("a missing connections scope does not fail the export", { timeout: 30_000 }, async () => {
  const mock = await startMock({ allowConnections: false });
  const out = await tempDir();
  try {
    const result = await runCli(
      ["export", "--out", out.dir, "--format", "json", "--users-source", "list"],
      credentialEnv(mock.baseUrl),
    );
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stderr, /read:connections/);
    const bundle = JSON.parse(await readFile(join(out.dir, "auth0-iga.json"), "utf8")) as {
      catalog: { connections: unknown[] };
    };
    assert.deepEqual(bundle.catalog.connections, []);
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("rejected credentials fail without printing the secret", { timeout: 30_000 }, async () => {
  const mock = await startMock();
  const out = await tempDir();
  const wrongSecret = "wrong-secret-value-should-not-print";
  try {
    const result = await runCli(
      ["export", "--out", out.dir, "--users-source", "list"],
      credentialEnv(mock.baseUrl, { AUTH0_CLIENT_SECRET: wrongSecret }),
    );
    assert.equal(result.code, 2);
    assert.equal(result.stderr.includes(wrongSecret), false);
    assert.match(result.stderr, /credentials|401|Unauthorized/i);
  } finally {
    await mock.close();
    await out.remove();
  }
});

test("config file credentials work and a missing domain does not echo the secret", { timeout: 30_000 }, async () => {
  const mock = await startMock();
  const out = await tempDir();
  const configDir = await tempDir();
  try {
    const configPath = join(configDir.dir, "auth0-iga.config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        domain: TENANT_DOMAIN,
        clientId: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      }),
      "utf8",
    );
    const result = await runCli(
      ["export", "--config", configPath, "--out", out.dir, "--format", "json", "--users-source", "list"],
      childEnv({ AUTH0_BASE_URL: mock.baseUrl }),
    );
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.stderr.includes(CLIENT_SECRET), false);

    const missing = await runCli(
      ["export", "--out", out.dir],
      childEnv({ AUTH0_CLIENT_ID: CLIENT_ID, AUTH0_CLIENT_SECRET: CLIENT_SECRET }),
    );
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /AUTH0_DOMAIN is required/);
    assert.equal(missing.stderr.includes(CLIENT_SECRET), false);
  } finally {
    await mock.close();
    await out.remove();
    await configDir.remove();
  }
});

test("scopes and help commands", async () => {
  const scopes = await runCli(["scopes"], childEnv({}));
  assert.equal(scopes.code, 0);
  assert.match(scopes.stdout, /read:users/);
  assert.match(scopes.stdout, /read:organization_member_roles/);
  const help = await runCli(["--help"], childEnv({}));
  assert.equal(help.code, 0);
  assert.match(help.stdout, /--users-source/);
  const version = await runCli(["--version"], childEnv({}));
  assert.equal(version.stdout.trim(), "0.1.0");
});
