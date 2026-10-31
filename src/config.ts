import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { ConfigError } from "./errors.js";
import type { OutputFormat } from "./output/write.js";

export type UsersSourceMode = "auto" | "list" | "export";

export interface ResolvedConfig {
  domain: string;
  clientId: string;
  clientSecret: string;
  audience?: string;
  baseUrl?: string;
  out: string;
  formats: OutputFormat[];
  usersSource: UsersSourceMode;
  exportThreshold: number;
  perPage: number;
  applicationName: string;
  maxRetries: number;
  jobPollMs: number;
  jobPollAttempts: number;
}

interface FileConfig {
  domain?: string;
  clientId?: string;
  clientSecret?: string;
  audience?: string;
  baseUrl?: string;
  out?: string;
  format?: string | string[];
  usersSource?: string;
  exportThreshold?: number;
  perPage?: number;
  applicationName?: string;
  maxRetries?: number;
  jobPollMs?: number;
}

const FILE_KEYS = new Set([
  "domain",
  "clientId",
  "clientSecret",
  "audience",
  "baseUrl",
  "out",
  "format",
  "usersSource",
  "exportThreshold",
  "perPage",
  "applicationName",
  "maxRetries",
  "jobPollMs",
]);

export interface ExportFlags {
  config?: string;
  out?: string;
  format?: string;
  usersSource?: string;
  exportThreshold?: number;
  perPage?: number;
  applicationName?: string;
  baseUrl?: string;
  jobPollMs?: number;
  maxRetries?: number;
}

export type ParsedArgs =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "scopes" }
  | { kind: "export"; flags: ExportFlags };

function integerOption(value: string | undefined, flag: string, min: number, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) throw new ConfigError(`${flag} must be an integer`);
  const parsed = Number(value);
  if (parsed < min || parsed > max) throw new ConfigError(`${flag} must be between ${min} and ${max}`);
  return parsed;
}

export function parseArgv(argv: string[]): ParsedArgs {
  if (argv.includes("--help") || argv.includes("-h")) return { kind: "help" };
  if (argv.includes("--version")) return { kind: "version" };
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        config: { type: "string" },
        out: { type: "string" },
        format: { type: "string" },
        "users-source": { type: "string" },
        "export-threshold": { type: "string" },
        "per-page": { type: "string" },
        "application-name": { type: "string" },
        "base-url": { type: "string" },
        "job-poll-ms": { type: "string" },
        "max-retries": { type: "string" },
      },
    });
  } catch (err) {
    throw new ConfigError(err instanceof Error ? err.message : String(err));
  }
  if (parsed.positionals.length > 1) {
    throw new ConfigError(`unexpected argument ${parsed.positionals[1]}`);
  }
  const command = parsed.positionals[0] ?? "";
  if (command === "scopes") return { kind: "scopes" };
  if (command !== "export") {
    throw new ConfigError(
      command ? `unknown command ${command}` : "missing command (expected export or scopes). Try --help.",
    );
  }
  const values = parsed.values;
  const text = (value: unknown): string | undefined => (typeof value === "string" ? value : undefined);
  return {
    kind: "export",
    flags: {
      config: text(values.config),
      out: text(values.out),
      format: text(values.format),
      usersSource: text(values["users-source"]),
      exportThreshold: integerOption(text(values["export-threshold"]), "--export-threshold", 0, 10_000_000),
      perPage: integerOption(text(values["per-page"]), "--per-page", 1, 100),
      applicationName: text(values["application-name"]),
      baseUrl: text(values["base-url"]),
      jobPollMs: integerOption(text(values["job-poll-ms"]), "--job-poll-ms", 0, 60_000),
      maxRetries: integerOption(text(values["max-retries"]), "--max-retries", 0, 10),
    },
  };
}

const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;

export function assertDomain(domain: string): string {
  const normalized = domain.trim().toLowerCase();
  if (normalized.includes("://") || normalized.includes("/")) {
    throw new ConfigError("AUTH0_DOMAIN must be a bare hostname, for example tenant.example.auth0.com");
  }
  if (!DOMAIN_PATTERN.test(normalized)) {
    throw new ConfigError("AUTH0_DOMAIN must be a bare hostname, for example tenant.example.auth0.com");
  }
  return normalized;
}

export function assertBaseUrl(baseUrl: string): string {
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new ConfigError("base URL is not a valid URL");
  }
  if (url.username || url.password) throw new ConfigError("base URL must not include credentials");
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError("base URL must use http or https");
  }
  return baseUrl.replace(/\/$/, "");
}

function envString(env: NodeJS.ProcessEnv, key: string): string | undefined {
  const value = env[key];
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function parseFormats(value: string | string[] | undefined): OutputFormat[] | undefined {
  if (value === undefined) return undefined;
  const parts = (Array.isArray(value) ? value.join(",") : value)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 1 && parts[0] === "all") return ["csv", "json", "scim"];
  const formats: OutputFormat[] = [];
  for (const part of parts) {
    if (part !== "csv" && part !== "json" && part !== "scim") {
      throw new ConfigError(`unknown format ${part} (expected csv, json, scim, or all)`);
    }
    if (!formats.includes(part)) formats.push(part);
  }
  if (formats.length === 0) throw new ConfigError("at least one output format is required");
  return formats;
}

function parseUsersSource(value: string | undefined): UsersSourceMode | undefined {
  if (value === undefined) return undefined;
  if (value === "auto" || value === "list" || value === "export") return value;
  throw new ConfigError("users source must be auto, list, or export");
}

async function readConfigFile(path: string): Promise<FileConfig> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    const code = err && typeof err === "object" && "code" in err ? String(err.code) : "";
    throw new ConfigError(code === "ENOENT" ? `config file not found: ${path}` : `could not read config file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new ConfigError(`config file is not valid JSON: ${path}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ConfigError("config file must be a JSON object");
  }
  const unknown = Object.keys(parsed).filter((key) => !FILE_KEYS.has(key));
  if (unknown.length > 0) throw new ConfigError(`unknown config file field ${unknown.join(", ")}`);
  return parsed as FileConfig;
}

function numberFromFile(value: number | undefined, field: string, min: number, max: number): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new ConfigError(`${field} must be an integer between ${min} and ${max}`);
  }
  return value;
}

export async function loadConfig(flags: ExportFlags, env: NodeJS.ProcessEnv = process.env): Promise<ResolvedConfig> {
  const configPath = flags.config ?? envString(env, "AUTH0_CONFIG");
  const file = configPath ? await readConfigFile(configPath) : {};
  const domainValue = envString(env, "AUTH0_DOMAIN") ?? file.domain;
  if (!domainValue) throw new ConfigError("AUTH0_DOMAIN is required (environment variable or config file)");
  const resolvedDomain = assertDomain(domainValue);
  const clientId = envString(env, "AUTH0_CLIENT_ID") ?? file.clientId ?? "";
  const clientSecret = envString(env, "AUTH0_CLIENT_SECRET") ?? file.clientSecret ?? "";
  if (!clientId) throw new ConfigError("AUTH0_CLIENT_ID is required (environment variable or config file)");
  if (!clientSecret) throw new ConfigError("AUTH0_CLIENT_SECRET is required (environment variable or config file)");

  const audience = envString(env, "AUTH0_AUDIENCE") ?? file.audience;
  const baseUrlValue = flags.baseUrl ?? envString(env, "AUTH0_BASE_URL") ?? file.baseUrl;
  const usersSource =
    parseUsersSource(flags.usersSource) ??
    parseUsersSource(envString(env, "AUTH0_USERS_SOURCE")) ??
    parseUsersSource(file.usersSource) ??
    "auto";
  const formats = parseFormats(flags.format) ?? parseFormats(envString(env, "AUTH0_FORMAT")) ?? parseFormats(file.format) ?? [
    "csv",
    "json",
  ];
  const applicationName =
    flags.applicationName ??
    envString(env, "AUTH0_APPLICATION_NAME") ??
    file.applicationName ??
    `Auth0 (${resolvedDomain})`;

  return {
    domain: resolvedDomain,
    clientId,
    clientSecret,
    audience,
    baseUrl: baseUrlValue ? assertBaseUrl(baseUrlValue) : undefined,
    out: flags.out ?? envString(env, "AUTH0_OUT") ?? file.out ?? "out",
    formats,
    usersSource,
    exportThreshold:
      flags.exportThreshold ??
      numberFromFile(file.exportThreshold, "exportThreshold", 0, 10_000_000) ??
      1000,
    perPage: flags.perPage ?? numberFromFile(file.perPage, "perPage", 1, 100) ?? 50,
    applicationName,
    maxRetries: flags.maxRetries ?? numberFromFile(file.maxRetries, "maxRetries", 0, 10) ?? 5,
    jobPollMs: flags.jobPollMs ?? numberFromFile(file.jobPollMs, "jobPollMs", 0, 60_000) ?? 1000,
    jobPollAttempts: 60,
  };
}
