import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { parseArgs } from "node:util";
import { ConfigError } from "./errors.js";
import type { GroupRoleMapping } from "./model/types.js";
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
  includeSystemScopes: boolean;
  groupAttributes: string[];
  groupRoleMap: GroupRoleMapping[];
}

/** Root attributes enterprise connections use for groups: native Azure AD and SAML send `groups`, Azure AD over SAML or OIDC sends `group_ids`. */
export const DEFAULT_GROUP_ATTRIBUTES = ["groups", "group_ids"];

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
  includeSystemScopes?: boolean;
  groupAttributes?: string | string[];
  groupRoleMap?: string;
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
  "includeSystemScopes",
  "groupAttributes",
  "groupRoleMap",
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
  includeSystemScopes?: boolean;
  groupAttributes?: string;
  groupRoleMap?: string;
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
        "include-system-scopes": { type: "boolean" },
        "group-attributes": { type: "string" },
        "group-role-map": { type: "string" },
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
      includeSystemScopes: values["include-system-scopes"] === true ? true : undefined,
      groupAttributes: text(values["group-attributes"]),
      groupRoleMap: text(values["group-role-map"]),
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

function parseBoolean(value: string | undefined, name: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new ConfigError(`${name} must be true or false`);
}

function booleanFromFile(value: unknown, field: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new ConfigError(`${field} must be true or false`);
  return value;
}

const ATTRIBUTE_SEGMENT = /^[A-Za-z0-9_$-]+$/;

/**
 * Group attribute paths are root attributes (`groups`) or `app_metadata` paths
 * (`app_metadata.roles`). `user_metadata` is refused: the user can edit it, so it is
 * not evidence of access. `none` turns group capture off.
 */
export function parseGroupAttributes(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  const parts = (Array.isArray(value) ? value.join(",") : value)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length === 1 && parts[0] === "none") return [];
  for (const path of parts) {
    const segments = path.split(".");
    if (!segments.every((segment) => ATTRIBUTE_SEGMENT.test(segment))) {
      throw new ConfigError(`group attribute ${path} is not a dotted attribute path`);
    }
    if (segments[0] === "user_metadata") {
      throw new ConfigError(`group attribute ${path} is in user_metadata, which the user can edit; use app_metadata or a root attribute`);
    }
    if (segments[0] === "identities") {
      throw new ConfigError(`group attribute ${path} is not supported; identity profile data is never read`);
    }
  }
  return [...new Set(parts)];
}

async function readGroupRoleMap(path: string): Promise<GroupRoleMapping[]> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    throw new ConfigError(`could not read group-role map: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new ConfigError(`group-role map is not valid JSON: ${path}`);
  }
  if (!Array.isArray(parsed)) throw new ConfigError("group-role map must be a JSON array of { connection?, group, role }");
  return parsed.map((entry, index) => {
    const record = entry && typeof entry === "object" && !Array.isArray(entry) ? (entry as Record<string, unknown>) : {};
    const unknown = Object.keys(record).filter((key) => !["connection", "group", "role"].includes(key));
    const field = (key: string) => (typeof record[key] === "string" ? (record[key] as string).trim() : "");
    if (unknown.length > 0 || !field("group") || !field("role") || ("connection" in record && !field("connection"))) {
      throw new ConfigError(`group-role map entry ${index + 1} must be { "connection"?: string, "group": string, "role": string }`);
    }
    const mapping: GroupRoleMapping = { group: field("group"), role: field("role") };
    if (field("connection")) mapping.connection = field("connection");
    return mapping;
  });
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
  // A map path in the config file is relative to that file.
  const groupRoleMapPath =
    flags.groupRoleMap ??
    envString(env, "AUTH0_GROUP_ROLE_MAP") ??
    (file.groupRoleMap && configPath ? resolve(dirname(configPath), file.groupRoleMap) : undefined);
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
    includeSystemScopes:
      flags.includeSystemScopes ??
      parseBoolean(envString(env, "AUTH0_INCLUDE_SYSTEM_SCOPES"), "AUTH0_INCLUDE_SYSTEM_SCOPES") ??
      booleanFromFile(file.includeSystemScopes, "includeSystemScopes") ??
      false,
    groupAttributes:
      parseGroupAttributes(flags.groupAttributes) ??
      parseGroupAttributes(envString(env, "AUTH0_GROUP_ATTRIBUTES")) ??
      parseGroupAttributes(file.groupAttributes) ??
      DEFAULT_GROUP_ATTRIBUTES,
    groupRoleMap: groupRoleMapPath ? await readGroupRoleMap(groupRoleMapPath) : [],
  };
}
