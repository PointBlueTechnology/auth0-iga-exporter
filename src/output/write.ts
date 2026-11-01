import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { IgBundle } from "../model/types.js";
import { accountsToCsv, assignmentsToCsv, hierarchyToCsv, permissionsToCsv } from "./csv.js";
import type { ScimDocuments } from "./scim.js";

export type OutputFormat = "csv" | "json" | "scim";

export interface WrittenFiles {
  directory: string;
  files: string[];
}

function json(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export async function writeExport(options: {
  directory: string;
  formats: OutputFormat[];
  bundle: IgBundle;
  scim: ScimDocuments;
}): Promise<WrittenFiles> {
  await mkdir(options.directory, { recursive: true, mode: 0o700 });
  const files: string[] = [];
  const write = async (name: string, contents: string): Promise<void> => {
    const path = join(options.directory, name);
    await writeFile(path, contents, { encoding: "utf8", mode: 0o600 });
    files.push(path);
  };

  if (options.formats.includes("csv")) {
    await write("accounts.csv", accountsToCsv(options.bundle.accounts));
    await write("permissions.csv", permissionsToCsv(options.bundle.permissions));
    await write("assignments.csv", assignmentsToCsv(options.bundle.assignments));
    await write("permission-hierarchy.csv", hierarchyToCsv(options.bundle.permissionHierarchy));
  }
  if (options.formats.includes("json")) {
    await write("auth0-iga.json", json(options.bundle));
  }
  if (options.formats.includes("scim")) {
    await write("scim-users.json", json(options.scim.users));
    await write("scim-groups.json", json(options.scim.groups));
  }

  const manifest = {
    schema: options.bundle.schema,
    generator: options.bundle.generator,
    exportedAt: options.bundle.meta.exportedAt,
    domain: options.bundle.meta.domain,
    applicationName: options.bundle.meta.applicationName,
    usersSource: options.bundle.meta.usersSource,
    formats: options.formats,
    counts: {
      accounts: options.bundle.accounts.length,
      permissions: options.bundle.permissions.length,
      assignments: options.bundle.assignments.length,
      permissionHierarchy: options.bundle.permissionHierarchy.length,
    },
    files: files.map((file) => file.slice(options.directory.length + 1)),
  };
  await write("manifest.json", json(manifest));
  return { directory: options.directory, files };
}
