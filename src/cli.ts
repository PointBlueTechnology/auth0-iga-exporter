#!/usr/bin/env node
import { pathToFileURL } from "node:url";
import { formatApiError } from "./auth0/api-error.js";
import { loadConfig, parseArgv } from "./config.js";
import { ConfigError, ExportError } from "./errors.js";
import { helpText } from "./help.js";
import { createLogger } from "./log.js";
import { redact } from "./redact.js";
import { exportTenant } from "./run.js";
import { formatScopesText } from "./scopes.js";
import { VERSION } from "./version.js";

export async function run(argv: string[]): Promise<number> {
  let secrets: string[] = [];
  try {
    const parsed = parseArgv(argv);
    if (parsed.kind === "help") {
      console.log(helpText());
      return 0;
    }
    if (parsed.kind === "version") {
      console.log(VERSION);
      return 0;
    }
    if (parsed.kind === "scopes") {
      console.log(formatScopesText());
      return 0;
    }
    const config = await loadConfig(parsed.flags);
    secrets = [config.clientSecret];
    await exportTenant(config, createLogger(secrets));
    return 0;
  } catch (err) {
    const message =
      err instanceof ConfigError || err instanceof ExportError ? err.message : formatApiError(err);
    console.error(`error: ${redact(message, secrets)}`);
    return err instanceof ConfigError ? 1 : 2;
  }
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) {
  run(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (err: unknown) => {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`error: ${message}`);
      process.exitCode = 2;
    },
  );
}
