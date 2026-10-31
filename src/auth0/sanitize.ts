import type {
  RawApi,
  RawApplication,
  RawConnection,
  RawIdentity,
  RawUser,
} from "../model/types.js";

/**
 * Wire shapes we read. Secret fields are listed so callers can see they exist
 * on Auth0 payloads, and so tests can pass them. The mappers below never copy them.
 */
export interface Auth0IdentityRecord {
  provider?: string;
  connection?: string;
  user_id?: string;
  isSocial?: boolean;
  access_token?: string;
  access_token_secret?: string;
  refresh_token?: string;
  profileData?: unknown;
}

export interface Auth0UserRecord {
  user_id?: string;
  email?: string;
  email_verified?: boolean | string;
  username?: string;
  name?: string;
  nickname?: string;
  given_name?: string;
  family_name?: string;
  created_at?: string;
  updated_at?: string;
  last_login?: string;
  logins_count?: number | string;
  blocked?: boolean | string;
  identities?: Auth0IdentityRecord[] | string;
}

export interface Auth0ClientRecord {
  client_id?: string;
  name?: string;
  app_type?: string;
  description?: string;
  client_secret?: string;
  signing_keys?: unknown;
  encryption_key?: unknown;
}

export interface Auth0ResourceServerRecord {
  id?: string;
  name?: string;
  identifier?: string;
  is_system?: boolean;
  scopes?: Array<{ value?: string; description?: string }>;
  signing_secret?: string;
}

export interface Auth0ConnectionRecord {
  id?: string;
  name?: string;
  strategy?: string;
  display_name?: string;
  options?: unknown;
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function asBool(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return undefined;
}

function toIdentity(input: Auth0IdentityRecord): RawIdentity | undefined {
  const provider = asString(input.provider) ?? "";
  const connection = asString(input.connection) ?? "";
  const userId = asString(input.user_id) ?? "";
  if (!provider && !connection && !userId) return undefined;
  const identity: RawIdentity = { provider, connection, userId };
  if (typeof input.isSocial === "boolean") identity.isSocial = input.isSocial;
  return identity;
}

function parseIdentities(value: Auth0UserRecord["identities"]): RawIdentity[] {
  let records: unknown = value;
  if (typeof value === "string") {
    try {
      records = JSON.parse(value) as unknown;
    } catch {
      return [];
    }
  }
  if (!Array.isArray(records)) return [];
  const identities: RawIdentity[] = [];
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const identity = toIdentity(record as Auth0IdentityRecord);
    if (identity) identities.push(identity);
  }
  return identities;
}

/** Map a Management API user, dropping identity-provider tokens and profile blobs. */
export function toRawUser(input: Auth0UserRecord): RawUser | undefined {
  const userId = asString(input.user_id);
  if (!userId) return undefined;
  const user: RawUser = {
    userId,
    blocked: asBool(input.blocked) ?? false,
    identities: parseIdentities(input.identities),
  };
  const email = asString(input.email);
  const emailVerified = asBool(input.email_verified);
  const username = asString(input.username);
  const name = asString(input.name);
  const nickname = asString(input.nickname);
  const givenName = asString(input.given_name);
  const familyName = asString(input.family_name);
  const createdAt = asString(input.created_at);
  const updatedAt = asString(input.updated_at);
  const lastLogin = asString(input.last_login);
  const loginsCount = asNumber(input.logins_count);
  if (email) user.email = email;
  if (emailVerified !== undefined) user.emailVerified = emailVerified;
  if (username) user.username = username;
  if (name) user.name = name;
  if (nickname) user.nickname = nickname;
  if (givenName) user.givenName = givenName;
  if (familyName) user.familyName = familyName;
  if (createdAt) user.createdAt = createdAt;
  if (updatedAt) user.updatedAt = updatedAt;
  if (lastLogin) user.lastLogin = lastLogin;
  if (loginsCount !== undefined) user.loginsCount = loginsCount;
  return user;
}

/** Map an application. Client secrets and keys are not read. */
export function toRawApplication(input: Auth0ClientRecord): RawApplication | undefined {
  const clientId = asString(input.client_id);
  if (!clientId) return undefined;
  return {
    clientId,
    name: asString(input.name) ?? clientId,
    appType: asString(input.app_type) ?? "",
    description: asString(input.description) ?? "",
  };
}

/** Map an API. The signing secret is not read. */
export function toRawApi(input: Auth0ResourceServerRecord): RawApi | undefined {
  const identifier = asString(input.identifier);
  if (!identifier) return undefined;
  const scopes = [];
  for (const scope of input.scopes ?? []) {
    const value = asString(scope.value);
    if (!value) continue;
    scopes.push({ value, description: asString(scope.description) ?? "" });
  }
  return {
    id: asString(input.id) ?? identifier,
    name: asString(input.name) ?? identifier,
    identifier,
    isSystem: input.is_system === true,
    scopes,
  };
}

/** Map a connection. `options` often holds IdP client secrets, so it is dropped. */
export function toRawConnection(input: Auth0ConnectionRecord): RawConnection | undefined {
  const id = asString(input.id);
  const name = asString(input.name);
  if (!id || !name) return undefined;
  return {
    id,
    name,
    strategy: asString(input.strategy) ?? "",
    displayName: asString(input.display_name) ?? "",
  };
}
