# auth0-iga-exporter

Export an Auth0 tenant into files an identity-governance platform can certify.

Auth0 is often the system of record for workforce and customer logins, while access reviews happen somewhere else. Reviewers need the accounts, the entitlements on those accounts, and the finer permissions those entitlements grant. This tool is a read-only extract for that cycle. It talks to the Auth0 Management API with a machine-to-machine application and writes:

- CSV shaped for an **OpenText Identity Governance** application collector (accounts, permissions, assignments, and permission hierarchy)
- one JSON bundle with the same model plus a sanitized catalog
- optional SCIM 2.0 Users and Groups, which SailPoint, Saviynt, and other IGA tools already know how to read

Version 0.1 is a command-line tool. It does not write back to Auth0.

## Why TypeScript

The collector is TypeScript on Node.js, using the official [`auth0`](https://github.com/auth0/node-auth0) package (node-auth0 7.6.0). That SDK is the supported way to call the Management API: it performs the client-credentials grant, caches the access token, walks both offset and checkpoint pagination, and retries HTTP 408, 429, and 5xx with `Retry-After` and exponential backoff.

OpenText Identity Governance's own collectors are Java and run inside the IG appliance. Shipping a JAR means an IG SDK, a change window, and a customer who is willing to install code on the governance server. A CLI that emits the CSV the built-in application collector already maps is something a consultant can run from a workstation, a container, or a scheduled job, and hand to IG as a file drop. A direct IG collector template is on the roadmap for teams that want IG to pull on its own schedule.

## Quick start

Requires Node.js 22 (or any current release that satisfies `engines` in `package.json`: `^20.19`, `^22.12`, or newer).

```bash
git clone https://github.com/PointBlueTechnology/auth0-iga-exporter.git
cd auth0-iga-exporter
npm ci
npm run build
```

Create a machine-to-machine application and authorize it for the Auth0 Management API. In the dashboard: Applications → APIs → Auth0 Management API → Machine to Machine Applications → authorize the app, and select only the scopes in the next section.

With the [Auth0 CLI](https://github.com/auth0/auth0-cli):

```bash
auth0 login
auth0 apps create --name "IGA exporter" --type m2m
auth0 client-grants create \
  --client-id "$AUTH0_CLIENT_ID" \
  --audience "https://$AUTH0_DOMAIN/api/v2/" \
  --scopes "read:users,read:roles,read:organizations,read:organization_members,read:organization_member_roles,read:clients,read:resource_servers,read:connections"
```

The audience has a trailing slash. That is the default Management API audience the SDK requests.

Put the credentials in the environment. Do not pass the secret on the command line. There is no `--client-secret` flag, so it does not show up in shell history.

```bash
export AUTH0_DOMAIN="tenant.example.auth0.com"   # bare hostname, no https://
export AUTH0_CLIENT_ID="..."
export AUTH0_CLIENT_SECRET="..."

node dist/cli.js export --out ./out --format all
```

Or `npx auth0-iga-exporter export` after `npm link`. A JSON config file can hold the non-secret settings. Copy [`auth0-iga.config.example.json`](auth0-iga.config.example.json) and point at it with `--config` or `AUTH0_CONFIG`. Environment variables override the file. See [`.env.example`](.env.example).

```text
exported 3 accounts, 12 permissions, 5 assignments (list)
out/accounts.csv
out/permissions.csv
out/assignments.csv
out/permission-hierarchy.csv
out/auth0-iga.json
out/scim-users.json
out/scim-groups.json
out/manifest.json
```

`auth0-iga-exporter scopes` prints the scope list. `auth0-iga-exporter --help` prints the flags.

## Scopes

Authorize the machine-to-machine app for `https://<domain>/api/v2/` with these **read** scopes only.

| Scope | Required | Used for |
| --- | --- | --- |
| `read:users` | yes | List users, read the user total, and run the bulk user export job. Also required, with `read:roles`, to list users on a role. |
| `read:roles` | yes | Roles, the permissions on each role, and direct role membership. |
| `read:organizations` | yes | Organizations. |
| `read:organization_members` | yes | Organization membership. |
| `read:organization_member_roles` | yes | Roles held inside an organization when the member payload does not already include them. |
| `read:clients` | yes | Applications. Client secrets are discarded and never written. |
| `read:resource_servers` | yes | APIs and their scopes. Signing secrets are discarded and never written. |
| `read:connections` | no | Connection catalog (id, name, strategy). A 403 skips the catalog and the export continues. |

Do not grant `create:*`, `update:*`, `delete:*`, `read:client_keys`, or `read:user_idp_tokens`. Identity-provider tokens are not an access-review attribute. If a payload contains `access_token`, `refresh_token`, or `profileData` on an identity, those fields are dropped before anything is written.

## What it collects

| Auth0 object | How | Notes |
| --- | --- | --- |
| Users and linked identities | `GET /api/v2/users`, or the bulk export job | Provider, connection, `user_id`, blocked, last login, login count. |
| Roles | `GET /api/v2/roles` | |
| Role permissions | `GET /api/v2/roles/{id}/permissions` | API identifier + permission name. |
| Direct user-to-role assignments | `GET /api/v2/roles/{id}/users` | Direct assignments only. Auth0 does not return roles inherited through a group here. |
| Organizations | `GET /api/v2/organizations` | Checkpoint pagination. |
| Organization members and their org roles | `GET /api/v2/organizations/{id}/members`, then member roles if `roles` is absent | |
| Applications | `GET /api/v2/clients` | Name, client id, app type, description. |
| APIs and scopes | `GET /api/v2/resource-servers` | |
| Connections | `GET /api/v2/connections` | Catalog only. `options` is dropped because it often holds an IdP client secret. |
| SSO groups | User attributes named by `--group-attributes` (default `groups,group_ids`) | Groups an enterprise connection asserted at sign-in. See below. |

### SSO groups

Auth0 has no group object. An enterprise connection writes the groups the identity provider sent onto the user profile, and the attribute name depends on the connection:

| Connection | Attribute |
| --- | --- |
| Native Azure AD / Entra ID (with "Get user groups") | `groups`, group names |
| Azure AD over SAML or OIDC | `group_ids`, object ids |
| Generic SAML | Whatever the connection's mapping names. Map the IdP's group claim to `groups`. |
| Google Workspace (with "Get user groups") | `groups` |
| Okta Workforce | None. The connection does not pass groups; use a SAML connection to Okta instead. |

Each group value becomes a `GROUP` permission, scoped to the user's connection (`group:okta-workforce::Billing Admins`), with a `GROUP_MEMBER` assignment. Two IdPs that both send "Admins" are two entitlements.

`--group-attributes` takes root attributes and `app_metadata` paths, for tenants where an Action copies groups into `app_metadata` (`--group-attributes groups,app_metadata.groups`). `user_metadata` is refused because the user can edit it. `none` turns group capture off. Only the named attributes are read; the rest of `app_metadata` is never written.

Auth0 does not turn groups into roles. That is usually a post-login Action, and its mapping lives in code. `--group-role-map` takes the same mapping as data, so the hierarchy shows which role a group is meant to confer:

```json
[
  { "connection": "okta-workforce", "group": "Billing Admins", "role": "Billing Admin" },
  { "group": "Finance", "role": "rol_viewer" }
]
```

`role` is a role id or name. Without `connection`, the entry applies to the group on every connection. Each match adds a `GRANTS` link from the group to the role. It does not add a role assignment: if the Action really assigns the role through the Management API, that shows up as `DIRECT_ROLE` on its own. An entry that matches no exported group or no role is reported on stderr.

The values are what the IdP sent at a sign-in, not a live directory read. With the connection's default `set_user_root_attributes` (`on_each_login`), Auth0 rewrites them at every sign-in, so a user removed from a group in the IdP still shows the group until they sign in again. With `on_first_login`, they are never refreshed. For a review that must reflect the directory today, certify the groups in the IdP itself.

Tested live with a SAML connection: the groups the IdP asserted landed on the user as a root `groups` array, and the list and bulk-export paths produced the same `GROUP` permissions, assignments, and mapped `GRANTS` link.

Pagination uses the SDK's page iterator. `--per-page` (1–100, default 50) is the offset page size and the checkpoint `take`.

Rate limits: the SDK retries 408, 429, and 5xx. It honors `Retry-After` when that header is a positive number of seconds, otherwise it backs off from one second with jitter, up to `--max-retries` (default 5). The test suite points the CLI at a mock that returns 429 once and checks that the export still completes. The access token is cached for its lifetime, so a long export does not request a new token per call.

### Users on a large tenant

`GET /api/v2/users` is a search endpoint. Auth0 documents it as the wrong tool for a full extract, and it will not page past 1,000 users.

`--users-source` chooses the path:

- `auto` (default) requests one page with `include_totals=true`. If the reported total is at least `--export-threshold` (default 1000), it runs the bulk export job. Otherwise it pages the list.
- `list` always pages `GET /api/v2/users`, and stops at 1,000 with a warning.
- `export` always calls `POST /api/v2/jobs/users-exports` with `format=json` and no `connection_id`, which exports every connection. The CLI polls `GET /api/v2/jobs/{id}` (`--job-poll-ms`, default 1000) and downloads the file. The file is newline-delimited JSON, gzip-compressed when Auth0 sends it that way.

## Output

Files are written mode `0600` where the platform honors it. Treat the directory as personal data.

| File | Format | Contents |
| --- | --- | --- |
| `accounts.csv` | CSV | One row per Auth0 user. |
| `permissions.csv` | CSV | Roles, org membership, org roles, SSO groups, applications, APIs, and API scopes. |
| `assignments.csv` | CSV | Account-to-permission rows a reviewer certifies. |
| `permission-hierarchy.csv` | CSV | A role or org role **grants** an API scope. A mapped SSO group **grants** a role. An organization **contains** an org role. An API **contains** its scopes. |
| `auth0-iga.json` | JSON | The same four collections, plus a sanitized catalog. Schema `pointblue.auth0-iga-exporter/v0.1`. |
| `scim-users.json` | SCIM 2.0 ListResponse | Users. `active` is false when the Auth0 user is blocked. |
| `scim-groups.json` | SCIM 2.0 ListResponse | One group per role, organization, organization role, and SSO group. API scopes stay in the permission hierarchy under the role that grants them. |
| `manifest.json` | JSON | Counts, domain, users source, file list. No secrets. |

`--format` accepts `csv`, `json`, `scim`, or `all`. The default is `csv,json`.

Assignments are the review items:

| `assignmentType` | Meaning |
| --- | --- |
| `DIRECT_ROLE` | The user is assigned the Auth0 role directly. |
| `ORGANIZATION_MEMBER` | The user is a member of the organization. |
| `ORGANIZATION_ROLE` | The user holds that role inside that organization. The same tenant role in two orgs is two entitlements. |
| `GROUP_MEMBER` | The user's identity provider asserted that group at the last sign-in. |

Applications and APIs are catalog permissions with no account assignments. Auth0 does not have a human "member of this application" entitlement. Client grants (which machine clients may call which API) are not an end-user access review and are out of scope for 0.1.

The Auth0 Management API is a system API. It declares every tenant-administration scope, about 280 of them, and on a typical tenant no role grants any. By default its scopes become permissions only when a role grants them, so they don't bury the scopes a reviewer actually certifies. The full list stays in the `catalog` of `auth0-iga.json`. Pass `--include-system-scopes` (or set `includeSystemScopes: true`, or `AUTH0_INCLUDE_SYSTEM_SCOPES=true`) to emit them all.

`emailVerified` is `false` when the account has an email and Auth0 omits `email_verified`, which custom-database users often do. Auth0 treats a missing value as unverified. It is empty only when the account has no email.

`privileged` is a review hint computed by this tool. Auth0 has no privileged attribute. It is true when the account holds a role, organization role, or SSO group whose name contains admin, administrator, owner, or superuser (or their plurals) as a word, or a group that `--group-role-map` maps to such a role. "Billing Admin" and "Billing Admins" count. "Invoice Viewer" does not.

Cells that start with `=`, `+`, `-`, `@`, or a tab are prefixed with a single quote so a spreadsheet does not treat them as formulas.

A user who is referenced by a role or an organization but missing from the user extract is still emitted, so the assignment is not dangling. The description says the profile was not returned.

`accountSource` says how the account signs in, from its primary identity: `DATABASE` (an Auth0 database connection, including custom databases), `SOCIAL`, `ENTERPRISE` (SAML, Azure AD, OIDC, ADFS, and the other enterprise connections), `PASSWORDLESS` (email or SMS), or `UNKNOWN` for an account known only from a role or organization payload.

**Shared user_ids.** The account id is the Auth0 `user_id`, with one exception. A database user's id is `auth0|<id>` and carries no connection, so two custom-database connections whose scripts return the same upstream id produce two different users with one `user_id`. Auth0 accepts this. Social and enterprise ids include the connection (`samlp|okta-workforce|riley`) and cannot collide this way. When it happens, both accounts are exported as `<user_id>@<connection>`, the `userId` column keeps the raw value, and a warning names them. Role and organization payloads carry only the `user_id`, so their assignments are attached to every account that holds it, and each account's description says so.

## Sample output

**Fictional.** The files in [`examples/fictional-tenant`](examples/fictional-tenant) were generated from the mock tenant in this repository. They are not a customer export. The domain `tenant.example.auth0.test` does not exist.

The story in the sample: Avery Chen is a Billing Admin and a member of Northwind Traders, where she also holds Invoice Viewer. Jordan Blake is blocked and holds Invoice Viewer directly. Samir Okonkwo signs in with Google and is a Northwind member with no role. Contoso Ltd has no members. The Invoices API scopes hang off the roles through the hierarchy.

`accounts.csv` (three rows, header wrapped here):

```text
accountId,name,displayName,disabled,lastLogin,privileged,status,connection,provider
auth0|avery,avery.chen@example.com,"Chen, Avery",false,2026-04-30T15:04:00.000Z,true,ACTIVE,Username-Password-Authentication,auth0
auth0|jordan,jordan.blake@example.com,Jordan Blake,true,2025-11-02T08:00:00.000Z,false,BLOCKED,Username-Password-Authentication,auth0
google-oauth2|samir,samir.okonkwo@example.com,Samir Okonkwo,false,,false,ACTIVE,google-oauth2,google-oauth2
```

`assignments.csv`:

```text
accountId,permissionId,assignmentType
auth0|avery,organization-role:org_northwind:rol_viewer,ORGANIZATION_ROLE
auth0|avery,organization:org_northwind,ORGANIZATION_MEMBER
auth0|avery,role:rol_billingadmin,DIRECT_ROLE
auth0|jordan,role:rol_viewer,DIRECT_ROLE
google-oauth2|samir,organization:org_northwind,ORGANIZATION_MEMBER
```

`permission-hierarchy.csv` (excerpt):

```text
parentPermissionId,childPermissionId,relation
organization:org_northwind,organization-role:org_northwind:rol_viewer,CONTAINS
role:rol_billingadmin,scope:https://invoices.example.com::read:invoices,GRANTS
role:rol_billingadmin,scope:https://invoices.example.com::write:invoices,GRANTS
role:rol_viewer,scope:https://invoices.example.com::read:invoices,GRANTS
```

A SCIM user (Jordan would be `"active": false`):

```json
{
  "schemas": [
    "urn:ietf:params:scim:schemas:core:2.0:User",
    "urn:ietf:params:scim:schemas:extension:auth0:2.0:User"
  ],
  "id": "auth0|avery",
  "externalId": "auth0|avery",
  "userName": "avery.chen@example.com",
  "displayName": "Chen, Avery",
  "active": true,
  "emails": [{ "value": "avery.chen@example.com", "type": "work", "primary": true }]
}
```

Full files, including the JSON bundle and SCIM groups, are in the examples directory.

## OpenText Identity Governance mapping

Model the Auth0 tenant as one **application**. This export is an application source: the accounts in the tenant and the entitlements on those accounts. Publish people from the HR or IDM identity collector, and join them to these accounts.

Identity Governance's CSV application collector maps source columns onto collector attributes. The headers below use those attribute names so the mapping screen is one-to-one. Extra columns are extended account or permission attributes.

| CSV column | IG collector attribute | Auth0 source |
| --- | --- | --- |
| `accountId` | Account ID | `user_id`, or `<user_id>@<connection>` when two connections share the `user_id` |
| `name` | Name | Email, then username, then nickname, then `user_id` |
| `displayName` | Extended: display name | `name`, or given name plus family name |
| `description` | Description | Sign-in provider and connection |
| `email` | Extended: email | `email` |
| `idmAccountId` | User ID / IDM account id (identity join) | Email when present, otherwise `user_id` |
| `disabled` | Disabled | `blocked` (`true` / `false`) |
| `lastLogin` | Last Login | `last_login`, ISO-8601 UTC, blank if the user has never logged in |
| `privileged` | Privileged | Role-name heuristic described above |
| `status` | Extended: status | `ACTIVE` or `BLOCKED` |
| `connection` | Extended | Primary identity connection |
| `provider` | Extended | Primary identity provider |
| `userId` | Extended | Raw Auth0 `user_id` |
| `accountSource` | Extended | `DATABASE`, `SOCIAL`, `ENTERPRISE`, `PASSWORDLESS`, or `UNKNOWN` |
| `identities` | Extended | JSON array of `{provider, connection, userId, isSocial}` |
| `permissionId` | Permission ID | Stable id, for example `role:rol_billingadmin` or `scope:https://invoices.example.com::read:invoices` |
| `name` (permission) | Name | Role name, scope, organization display name, application name |
| `description` (permission) | Description | Auth0 description when it has one |
| `type` | Extended: permission type | `ROLE`, `ORGANIZATION_ROLE`, `ORGANIZATION`, `GROUP`, `API_SCOPE`, `API`, `APPLICATION` |
| `value` | Extended | Native Auth0 id or scope value |
| `applicationName` | Application name | The tenant, repeated on each row so files can be concatenated |
| `accountId` + `permissionId` | Account-permission assignment | The pair IG certifies. `assignmentType` can be stored as an extended attribute or ignored |
| `parentPermissionId` + `childPermissionId` | Permission hierarchy (permission holds permission) | `GRANTS` and `CONTAINS` |

Suggested review scope: import `ROLE`, `ORGANIZATION`, `ORGANIZATION_ROLE`, and `GROUP` as the permissions people certify, and load `permission-hierarchy.csv` so a Billing Admin review shows `read:invoices` and `write:invoices` underneath it. Leave `APPLICATION` and `API` in the catalog if you want reviewers to see the resource model; they have no holders in 0.1.

`idmAccountId` is the join to the identity publication. Email is the practical key when Auth0 and the identity source share it. It is not an Auth0 guarantee of uniqueness across social and database accounts.

### SailPoint and Saviynt

The same three CSVs are the usual account, entitlement, and account-entitlement feeds:

- SailPoint account schema: native identity = `accountId`, display name = `displayName`, disabled = `disabled`. Entitlements are the permission rows whose `type` is `ROLE`, `ORGANIZATION`, `ORGANIZATION_ROLE`, or `GROUP`. `scim-groups.json` is the same set as SCIM Group resources.
- Saviynt file import: `accounts.csv` corresponds to the account file, `permissions.csv` to entitlements, `assignments.csv` to account-entitlements. Rename or map columns to the tenant's import template. This repository does not ship a Saviynt XML connector.

## Security

- The machine-to-machine application should hold the read scopes above and nothing else. The exporter never calls a create, update, or delete endpoint.
- The client secret is read from the environment or a config file. Restrict the file (`chmod 600`) and do not commit it. `.gitignore` ignores `.env`.
- Logs go to stderr. Before a line is written, known secret values of at least 8 characters are replaced with `[redacted]`. The exit message on a 401 or 403 does not include the secret. Tokens are not logged.
- Application `client_secret`, API `signing_secret`, connection `options`, and identity-provider tokens are not copied into the model. The test tenant plants all four and asserts they are absent from stdout, stderr, and every output file.
- `--base-url` / `AUTH0_BASE_URL` rewrites the token and Management API calls to another origin. The client secret is sent to that host. It exists so the test suite can run the real SDK against a local mock. Do not point it at a server you do not trust. The CLI prints a warning when it is set.
- Output contains emails and user ids. Keep the directory with the same care as an access-review extract.
- CSV formula prefixes are neutralized so opening a file in a spreadsheet does not execute a cell.

## Docker

The image contains the CLI only. Pass the secret at runtime.

```bash
docker build -t auth0-iga-exporter .
mkdir -p out
docker run --rm \
  -e AUTH0_DOMAIN -e AUTH0_CLIENT_ID -e AUTH0_CLIENT_SECRET \
  -v "$PWD/out:/out" \
  --user "$(id -u):$(id -g)" \
  auth0-iga-exporter export --out /out --format all
```

`--user` makes the mounted `out` directory writable as the account that owns it. The image defaults to the `node` user.

## Schedule

A weekly file drop is enough for a certification campaign. [`examples/github-action-scheduled-export.yml`](examples/github-action-scheduled-export.yml) is a GitHub Actions workflow you can copy into `.github/workflows/`. It is not registered in this repository, so it does not run here. Store `AUTH0_DOMAIN`, `AUTH0_CLIENT_ID`, and `AUTH0_CLIENT_SECRET` as Actions secrets. The workflow uploads `export-out` as an artifact.

A Cloudflare Worker is a poor fit for 0.1. The export can run for minutes, write a directory of files, and download a gzip dump. A scheduled container or the GitHub Action above is the cheaper path. A Worker in front of an event stream is a later idea, once delta exports exist.

## Development

```bash
npm ci
npm test      # mocked Management API, no tenant
npm run lint
npm run build
```

Tests start an HTTP server that implements the token endpoint and the Management API routes the exporter calls, including pagination, a single 429 with `Retry-After`, a gzip user-export job, and a 403 on connections. The CLI is executed as a process against that server.

GitHub Actions (`.github/workflows/ci.yml`) runs lint, test, and build on Node.js 22. It has no Auth0 credentials.

`npm run generate-sample` rewrites `examples/fictional-tenant` from the mock.

## Roadmap

- **Incremental exports.** Keep a checkpoint (`updated_at`, or a Management API log cursor) and emit only accounts and assignments that changed, so a nightly run is a delta instead of a full snapshot.
- **Auth0 change events.** An Auth0 Action or Event Stream that publishes user, role, and organization changes as they happen, for IGA products that can consume a feed instead of a file.
- **OpenText IG collector template.** A CSV collector map, and later a collector definition IG can schedule itself, so the file drop is replaced by a pull.
- **Direct user permissions and client grants**, for tenants that assign API permissions to users outside roles, or that need machine-client entitlement reviews.
- **A local overlay** for permission owner, risk, and cost, which Auth0 does not store and IG reviewers usually want.

## About

[Point Blue Technology](https://github.com/PointBlueTechnology) publishes this as an open-source portfolio project. Jerry Combs consults on OpenText Identity Manager and Identity Governance, and previously engineered on OpenText / NetIQ Identity Manager. The exporter is the Auth0 side of that work: get the accounts and entitlements into a shape Identity Governance can review.

Licensed under the [Apache License 2.0](LICENSE).
