import type { IgAccount, IgAssignment, IgHierarchy, IgPermission } from "../model/types.js";

const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function neutralize(value: string): string {
  return FORMULA_PREFIX.test(value) ? `'${value}` : value;
}

export function encodeCell(value: string): string {
  const safe = neutralize(value);
  if (/[",\r\n]/.test(safe)) return `"${safe.replaceAll('"', '""')}"`;
  return safe;
}

export function toCsv(headers: string[], rows: string[][]): string {
  const lines = [headers.map(encodeCell).join(",")];
  for (const row of rows) lines.push(row.map(encodeCell).join(","));
  return `${lines.join("\n")}\n`;
}

function bool(value: boolean): string {
  return value ? "true" : "false";
}

function optionalBool(value: boolean | null): string {
  if (value === null) return "";
  return bool(value);
}

export const ACCOUNT_HEADERS = [
  "accountId",
  "name",
  "displayName",
  "description",
  "email",
  "username",
  "idmAccountId",
  "disabled",
  "lastLogin",
  "privileged",
  "status",
  "connection",
  "provider",
  "identities",
  "createdAt",
  "updatedAt",
  "loginsCount",
  "emailVerified",
  "givenName",
  "familyName",
] as const;

export function accountsToCsv(accounts: IgAccount[]): string {
  return toCsv(
    [...ACCOUNT_HEADERS],
    accounts.map((account) => [
      account.accountId,
      account.name,
      account.displayName,
      account.description,
      account.email,
      account.username,
      account.idmAccountId,
      bool(account.disabled),
      account.lastLogin,
      bool(account.privileged),
      account.status,
      account.connection,
      account.provider,
      JSON.stringify(account.identities),
      account.createdAt,
      account.updatedAt,
      account.loginsCount === null ? "" : String(account.loginsCount),
      optionalBool(account.emailVerified),
      account.givenName,
      account.familyName,
    ]),
  );
}

export const PERMISSION_HEADERS = [
  "permissionId",
  "name",
  "description",
  "type",
  "value",
  "applicationName",
] as const;

export function permissionsToCsv(permissions: IgPermission[]): string {
  return toCsv(
    [...PERMISSION_HEADERS],
    permissions.map((permission) => [
      permission.permissionId,
      permission.name,
      permission.description,
      permission.type,
      permission.value,
      permission.applicationName,
    ]),
  );
}

export const ASSIGNMENT_HEADERS = ["accountId", "permissionId", "assignmentType"] as const;

export function assignmentsToCsv(assignments: IgAssignment[]): string {
  return toCsv(
    [...ASSIGNMENT_HEADERS],
    assignments.map((assignment) => [assignment.accountId, assignment.permissionId, assignment.assignmentType]),
  );
}

export const HIERARCHY_HEADERS = ["parentPermissionId", "childPermissionId", "relation"] as const;

export function hierarchyToCsv(hierarchy: IgHierarchy[]): string {
  return toCsv(
    [...HIERARCHY_HEADERS],
    hierarchy.map((link) => [link.parentPermissionId, link.childPermissionId, link.relation]),
  );
}

/** Small RFC 4180 reader used by tests and by anyone checking a file by hand. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let inQuotes = false;
  const source = text.endsWith("\n") ? text.slice(0, -1) : text;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (inQuotes) {
      if (char === '"') {
        if (source[index + 1] === '"') {
          cell += '"';
          index += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cell += char;
      }
      continue;
    }
    if (char === '"') {
      inQuotes = true;
      continue;
    }
    if (char === ",") {
      row.push(cell);
      cell = "";
      continue;
    }
    if (char === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      continue;
    }
    if (char === "\r") continue;
    cell += char;
  }
  if (cell.length > 0 || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}
