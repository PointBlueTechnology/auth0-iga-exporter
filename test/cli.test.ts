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
  SAML_USER,
  SECRET_SIGNING,
  TENANT_DOMAIN,
  fictionalTenant,
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

function tenantWithSamlUser() {
  const fixture = fictionalTenant();
  fixture.users.push(structuredClone(SAML_USER));
  return fixture;
}

for (const usersSource of ["list", "export"]) {
  test(`SSO groups become GROUP permissions and map to roles (${usersSource})`, { timeout: 30_000 }, async () => {
    const mock = await startMock({ fixture: tenantWithSamlUser() });
    const out = await tempDir();
    try {
      const map = join(out.dir, "group-roles.json");
      await writeFile(
        map,
        JSON.stringify([
          { connection: "okta-workforce", group: "Billing Admins", role: "Billing Admin" },
          { group: "Engineering", role: "No Such Role" },
          { group: "Nobody Has This", role: "rol_viewer" },
        ]),
      );
      const result = await runCli(
        [
          "export",
          "--out",
          out.dir,
          "--format",
          "all",
          "--users-source",
          usersSource,
          "--job-poll-ms",
          "10",
          "--group-attributes",
          "groups,app_metadata.teams",
          "--group-role-map",
          map,
        ],
        credentialEnv(mock.baseUrl),
      );
      assert.equal(result.code, 0, result.stderr);
      assert.match(result.stderr, /"No Such Role".*matched no role/);
      assert.match(result.stderr, /"Nobody Has This".*matched no exported group/);

      const group = "group:okta-workforce::Billing Admins";
      const permissions = parseCsv(await readFile(join(out.dir, "permissions.csv"), "utf8"));
      const groups = permissions.filter((row) => row[3] === "GROUP").map((row) => row[0]);
      assert.deepEqual(groups.sort(), [group, "group:okta-workforce::Engineering", "group:okta-workforce::payments"]);

      const assignments = parseCsv(await readFile(join(out.dir, "assignments.csv"), "utf8"));
      const pairs = assignments.slice(1).map((row) => row.join("|"));
      assert.ok(pairs.includes(`samlp|okta-workforce|riley|${group}|GROUP_MEMBER`));
      assert.equal(pairs.some((pair) => pair.startsWith("samlp|okta-workforce|riley|role:")), false);

      const links = parseCsv(await readFile(join(out.dir, "permission-hierarchy.csv"), "utf8")).map((row) => row.join("|"));
      assert.ok(links.includes(`${group}|role:rol_billingadmin|GRANTS`));

      const accounts = parseCsv(await readFile(join(out.dir, "accounts.csv"), "utf8"));
      const riley = accounts.find((row) => row[0] === "samlp|okta-workforce|riley");
      assert.equal(riley?.[9], "true");

      const scim = JSON.parse(await readFile(join(out.dir, "scim-groups.json"), "utf8"));
      const scimGroup = scim.Resources.find((resource: { id: string }) => resource.id === group);
      assert.deepEqual(scimGroup.members.map((member: { value: string }) => member.value), ["samlp|okta-workforce|riley"]);

      const bundle = await readFile(join(out.dir, "auth0-iga.json"), "utf8");
      assert.equal(bundle.includes("support_tier"), false, "app_metadata outside the group paths is not written");
      if (usersSource === "export") {
        const fields = (mock.exportRequest as { fields: Array<{ name: string }> }).fields.map((field) => field.name);
        assert.ok(fields.includes("groups"));
        assert.ok(fields.includes("group_ids") === false);
        assert.ok(fields.includes("app_metadata"));
      }
    } finally {
      await mock.close();
      await out.remove();
    }
  });
}

for (const usersSource of ["list", "export"]) {
  test(`a user_id shared by two database connections keeps both accounts (${usersSource})`, { timeout: 30_000 }, async () => {
    const fixture = fictionalTenant();
    const twin = structuredClone(fixture.users.find((user) => user.user_id === "auth0|avery"));
    assert.ok(twin);
    twin.email = "avery.legacy@example.com";
    twin.identities = [{ provider: "auth0", connection: "legacy-db", user_id: "avery", isSocial: false }];
    fixture.users.push(twin);
    const mock = await startMock({ fixture });
    const out = await tempDir();
    try {
      const result = await runCli(
        ["export", "--out", out.dir, "--format", "csv", "--users-source", usersSource, "--job-poll-ms", "10"],
        credentialEnv(mock.baseUrl),
      );
      assert.equal(result.code, 0, result.stderr);
      assert.match(result.stdout, /exported 4 accounts/);
      assert.match(result.stderr, /user_id auth0\|avery is held by users on more than one connection/);
      const accounts = parseCsv(await readFile(join(out.dir, "accounts.csv"), "utf8"));
      const header = accounts[0] ?? [];
      const ids = accounts.slice(1).map((row) => row[0]);
      assert.ok(ids.includes("auth0|avery@legacy-db"));
      assert.ok(ids.includes("auth0|avery@Username-Password-Authentication"));
      const legacy = accounts.find((row) => row[0] === "auth0|avery@legacy-db") ?? [];
      assert.equal(legacy[header.indexOf("userId")], "auth0|avery");
      assert.equal(legacy[header.indexOf("accountSource")], "DATABASE");
      const pairs = parseCsv(await readFile(join(out.dir, "assignments.csv"), "utf8")).map((row) => row.join("|"));
      assert.ok(pairs.includes("auth0|avery@legacy-db|role:rol_billingadmin|DIRECT_ROLE"));
      assert.ok(pairs.includes("auth0|avery@Username-Password-Authentication|role:rol_billingadmin|DIRECT_ROLE"));
    } finally {
      await mock.close();
      await out.remove();
    }
  });
}

test("group attributes in user_metadata are refused", async () => {
  const result = await runCli(
    ["export", "--group-attributes", "user_metadata.groups"],
    credentialEnv("http://127.0.0.1:9"),
  );
  assert.equal(result.code === 0, false);
  assert.match(result.stderr, /user_metadata, which the user can edit/);
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
  assert.equal(version.stdout.trim(), "0.2.0");
});
