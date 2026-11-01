import { VERSION } from "./version.js";

export function helpText(): string {
  return `auth0-iga-exporter ${VERSION}

Export an Auth0 tenant into files an identity-governance platform can use
for access reviews. OpenText Identity Governance is the primary target.
The same files are ordinary CSV and JSON for SailPoint, Saviynt, and others.

Usage
  auth0-iga-exporter export [options]
  auth0-iga-exporter scopes
  auth0-iga-exporter --help
  auth0-iga-exporter --version

Credentials
  AUTH0_DOMAIN          Bare tenant hostname, such as tenant.example.auth0.com
  AUTH0_CLIENT_ID       Machine-to-machine application client id
  AUTH0_CLIENT_SECRET   Machine-to-machine application client secret
  AUTH0_AUDIENCE        Optional. Defaults to https://<domain>/api/v2/
  AUTH0_CONFIG          Optional JSON config file. Environment variables win.

  The client secret is read from the environment or the config file.
  There is no --client-secret flag, so the secret does not land in shell history.

Options
  --config <file>              JSON config file
  --out <dir>                  Output directory (default: out)
  --format <list>              csv, json, scim, or all (default: csv,json)
  --users-source <mode>        auto, list, or export (default: auto)
  --export-threshold <n>       In auto mode, use the bulk user export job when
                               the reported user total is at least n (default: 1000)
  --per-page <n>               Page size from 1 to 100 (default: 50)
  --application-name <name>    Name of the IG application (default: Auth0 (<domain>))
  --max-retries <n>            Retries for 408, 429, and 5xx (default: 5).
                               The Auth0 SDK waits on Retry-After, then backs off.
  --job-poll-ms <n>            Delay between bulk-export job polls (default: 1000)
  --base-url <url>             Send token and Management API calls to this origin.
                               Test hook. The client secret is sent there.

Users
  auto    Probe GET /api/v2/users. At or above the threshold, run the bulk
          export job, which is the supported way to enumerate a large tenant.
          Otherwise page the list endpoint. The list endpoint stops at 1,000 users.
  list    Always page GET /api/v2/users.
  export  Always run POST /api/v2/jobs/users-exports and download the NDJSON file.

Output
  accounts.csv, permissions.csv, assignments.csv, permission-hierarchy.csv
  auth0-iga.json
  scim-users.json, scim-groups.json
  manifest.json
`;
}
