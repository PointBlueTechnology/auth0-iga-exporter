import type { IgAccount, IgAssignment, IgPermission, NormalizedExport } from "../model/types.js";

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const AUTH0_USER_EXT = "urn:ietf:params:scim:schemas:extension:auth0:2.0:User";
const AUTH0_GROUP_EXT = "urn:ietf:params:scim:schemas:extension:auth0:2.0:Group";

interface ScimList {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: unknown[];
}

function list(resources: unknown[]): ScimList {
  return {
    schemas: [LIST_SCHEMA],
    totalResults: resources.length,
    startIndex: 1,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}

function userResource(account: IgAccount): Record<string, unknown> {
  const resource: Record<string, unknown> = {
    schemas: [USER_SCHEMA, AUTH0_USER_EXT],
    id: account.accountId,
    externalId: account.accountId,
    userName: account.name,
    displayName: account.displayName,
    active: !account.disabled,
    meta: {
      resourceType: "User",
      created: account.createdAt || undefined,
      lastModified: account.updatedAt || undefined,
    },
  };
  const name: Record<string, string> = { formatted: account.displayName };
  if (account.givenName) name.givenName = account.givenName;
  if (account.familyName) name.familyName = account.familyName;
  resource.name = name;
  if (account.email) {
    resource.emails = [{ value: account.email, type: "work", primary: true }];
  }
  resource[AUTH0_USER_EXT] = {
    userId: account.userId,
    accountSource: account.accountSource,
    connection: account.connection,
    provider: account.provider,
    lastLogin: account.lastLogin,
    loginsCount: account.loginsCount,
    blocked: account.disabled,
    identities: account.identities,
  };
  return resource;
}

function membersFor(permission: IgPermission, assignments: IgAssignment[], accounts: Map<string, IgAccount>) {
  const assignmentType =
    permission.type === "ROLE"
      ? "DIRECT_ROLE"
      : permission.type === "ORGANIZATION"
        ? "ORGANIZATION_MEMBER"
        : permission.type === "ORGANIZATION_ROLE"
          ? "ORGANIZATION_ROLE"
          : permission.type === "GROUP"
            ? "GROUP_MEMBER"
            : undefined;
  if (!assignmentType) return [];
  return assignments
    .filter(
      (assignment) => assignment.permissionId === permission.permissionId && assignment.assignmentType === assignmentType,
    )
    .map((assignment) => {
      const account = accounts.get(assignment.accountId);
      return {
        value: assignment.accountId,
        display: account?.displayName ?? assignment.accountId,
        type: "User",
      };
    });
}

function groupResource(
  permission: IgPermission,
  assignments: IgAssignment[],
  accounts: Map<string, IgAccount>,
): Record<string, unknown> {
  return {
    schemas: [GROUP_SCHEMA, AUTH0_GROUP_EXT],
    id: permission.permissionId,
    displayName: permission.name,
    members: membersFor(permission, assignments, accounts),
    meta: { resourceType: "Group" },
    [AUTH0_GROUP_EXT]: {
      type: permission.type,
      value: permission.value,
      description: permission.description,
    },
  };
}

export interface ScimDocuments {
  users: ScimList;
  groups: ScimList;
}

const GROUP_TYPES = new Set(["ROLE", "ORGANIZATION", "ORGANIZATION_ROLE", "GROUP"]);

export function toScim(normalized: NormalizedExport): ScimDocuments {
  const accounts = new Map(normalized.accounts.map((account) => [account.accountId, account]));
  const users = normalized.accounts.map(userResource);
  const groups = normalized.permissions
    .filter((permission) => GROUP_TYPES.has(permission.type))
    .map((permission) => groupResource(permission, normalized.assignments, accounts));
  return { users: list(users), groups: list(groups) };
}
