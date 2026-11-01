import { collectSnapshot } from "./auth0/collect.js";
import { createManagementClient } from "./auth0/client.js";
import type { ResolvedConfig } from "./config.js";
import type { Logger } from "./log.js";
import { normalize } from "./model/normalize.js";
import { toBundle } from "./output/bundle.js";
import { toScim } from "./output/scim.js";
import { writeExport } from "./output/write.js";

export async function exportTenant(config: ResolvedConfig, log: Logger): Promise<void> {
  if (config.baseUrl) {
    log.warn(
      `AUTH0_BASE_URL is set (${config.baseUrl}). The client secret is sent to that host's token endpoint. Use this only for a local mock or a host you trust.`,
    );
  }
  const client = createManagementClient(config);
  const snapshot = await collectSnapshot(client, config, log);
  const normalized = normalize(snapshot, { includeSystemScopes: config.includeSystemScopes });
  const written = await writeExport({
    directory: config.out,
    formats: config.formats,
    bundle: toBundle(snapshot, normalized),
    scim: toScim(normalized),
  });
  console.log(
    `exported ${normalized.accounts.length} accounts, ${normalized.permissions.length} permissions, ${normalized.assignments.length} assignments (${snapshot.usersSource})`,
  );
  for (const file of written.files) console.log(file);
}
