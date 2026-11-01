import {
  apiPermissionId,
  applicationPermissionId,
  groupPermissionId,
  organizationPermissionId,
  organizationRolePermissionId,
  rolePermissionId,
  scopePermissionId,
} from "./ids.js";
import type {
  GroupRoleMapping,
  IgAccount,
  IgAssignment,
  IgHierarchy,
  IgPermission,
  NormalizedExport,
  RawOrgMember,
  RawSnapshot,
  RawUser,
} from "./types.js";

const PRIVILEGED_NAME = /\b(admins?|administrators?|owners?|superusers?)\b/i;

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function firstIdentity(user: RawUser): { provider: string; connection: string } {
  const identity = user.identities[0];
  return {
    provider: identity?.provider ?? "",
    connection: identity?.connection ?? "",
  };
}

function accountName(user: RawUser): string {
  return user.email || user.username || user.nickname || user.userId;
}

function displayName(user: RawUser, fallback: string): string {
  if (user.name) return user.name;
  const joined = [user.givenName, user.familyName].filter(Boolean).join(" ");
  return joined || fallback;
}

function describeUser(user: RawUser, provider: string, connection: string): string {
  if (provider || connection) {
    return `Sign-in provider ${provider || "unknown"}, connection ${connection || "unknown"}`;
  }
  if (user.identities.length === 0) {
    return "Referenced by a role or organization membership, and not returned by the user export";
  }
  return "Auth0 account";
}

function toAccount(user: RawUser): IgAccount {
  const { provider, connection } = firstIdentity(user);
  const name = accountName(user);
  return {
    accountId: user.userId,
    name,
    displayName: displayName(user, name),
    description: describeUser(user, provider, connection),
    email: user.email ?? "",
    username: user.username ?? "",
    idmAccountId: user.email || user.userId,
    disabled: user.blocked,
    lastLogin: user.lastLogin ?? "",
    privileged: false,
    status: user.blocked ? "BLOCKED" : "ACTIVE",
    connection,
    provider,
    identities: user.identities.map((identity) => ({ ...identity })),
    createdAt: user.createdAt ?? "",
    updatedAt: user.updatedAt ?? "",
    loginsCount: user.loginsCount ?? null,
    // Auth0 omits email_verified on some users (custom-database imports, for one)
    // and treats that as unverified. Empty means there is no email to verify.
    emailVerified: user.emailVerified ?? (user.email ? false : null),
    givenName: user.givenName ?? "",
    familyName: user.familyName ?? "",
  };
}

function ensureUser(users: Map<string, RawUser>, userId: string, hint?: { email?: string; name?: string }): void {
  if (users.has(userId)) return;
  const stub: RawUser = { userId, blocked: false, identities: [] };
  if (hint?.email) stub.email = hint.email;
  if (hint?.name) stub.name = hint.name;
  users.set(userId, stub);
}

/**
 * Turn a tenant snapshot into the account / permission / assignment model
 * OpenText Identity Governance collects for an application.
 *
 * Direct review items are roles, organization membership, and organization roles.
 * API scopes hang off those roles through the permission hierarchy so a reviewer
 * can see what a role grants without certifying every scope as its own assignment.
 * Auth0 has no human user-to-application membership, so applications and APIs are
 * catalog permissions with no account assignments.
 *
 * The Management API is a system API that declares every tenant-administration
 * scope (about 280). Unless includeSystemScopes is set, its scopes become
 * permissions only when a role grants them. The catalog keeps the full list.
 *
 * Groups come from configured user attributes, usually `groups` asserted by an
 * enterprise connection at sign-in. Each one is a GROUP permission scoped to the
 * user's connection, with a GROUP_MEMBER assignment. Auth0 does not turn groups into
 * roles by itself, so a group-to-role map (when given) only adds GRANTS links: the
 * reviewer sees which role a group is meant to confer, not a role assignment.
 */
export function normalize(
  snapshot: RawSnapshot,
  options: { includeSystemScopes?: boolean; groupRoleMap?: GroupRoleMapping[] } = {},
): NormalizedExport {
  const users = new Map<string, RawUser>();
  for (const user of snapshot.users) users.set(user.userId, user);

  const permissions = new Map<string, IgPermission>();
  const assignments = new Map<string, IgAssignment>();
  const hierarchy = new Map<string, IgHierarchy>();

  const addPermission = (permission: IgPermission): void => {
    if (!permissions.has(permission.permissionId)) permissions.set(permission.permissionId, permission);
  };
  const addAssignment = (assignment: IgAssignment): void => {
    const key = `${assignment.accountId}\0${assignment.permissionId}\0${assignment.assignmentType}`;
    if (!assignments.has(key)) assignments.set(key, assignment);
  };
  const addLink = (link: IgHierarchy): void => {
    const key = `${link.parentPermissionId}\0${link.childPermissionId}\0${link.relation}`;
    if (!hierarchy.has(key)) hierarchy.set(key, link);
  };

  const applicationName = snapshot.applicationName;
  const scopeGrantsByRole = new Map<string, string[]>();
  const grantedScopeIds = new Set(
    snapshot.roles.flatMap((role) =>
      role.permissions.map((permission) =>
        scopePermissionId(permission.resourceServerIdentifier ?? "", permission.permissionName),
      ),
    ),
  );

  for (const api of snapshot.resourceServers) {
    const apiId = apiPermissionId(api.identifier);
    addPermission({
      permissionId: apiId,
      name: api.name,
      description: api.isSystem ? "Auth0 system API" : "Auth0 API (resource server)",
      type: "API",
      value: api.identifier,
      applicationName,
    });
    for (const scope of api.scopes) {
      const scopeId = scopePermissionId(api.identifier, scope.value);
      if (api.isSystem && !options.includeSystemScopes && !grantedScopeIds.has(scopeId)) continue;
      addPermission({
        permissionId: scopeId,
        name: scope.value,
        description: scope.description || `Scope on ${api.name}`,
        type: "API_SCOPE",
        value: scope.value,
        applicationName,
      });
      addLink({ parentPermissionId: apiId, childPermissionId: scopeId, relation: "CONTAINS" });
    }
  }

  for (const role of snapshot.roles) {
    const roleId = rolePermissionId(role.id);
    addPermission({
      permissionId: roleId,
      name: role.name,
      description: role.description || "Auth0 role",
      type: "ROLE",
      value: role.id,
      applicationName,
    });
    const granted: string[] = [];
    for (const permission of role.permissions) {
      const identifier = permission.resourceServerIdentifier ?? "";
      const scopeId = scopePermissionId(identifier, permission.permissionName);
      addPermission({
        permissionId: scopeId,
        name: permission.permissionName,
        description:
          permission.description ||
          (permission.resourceServerName
            ? `Permission on ${permission.resourceServerName}`
            : "Auth0 role permission"),
        type: "API_SCOPE",
        value: permission.permissionName,
        applicationName,
      });
      granted.push(scopeId);
      addLink({ parentPermissionId: roleId, childPermissionId: scopeId, relation: "GRANTS" });
    }
    scopeGrantsByRole.set(role.id, granted);
    for (const userId of role.userIds) {
      ensureUser(users, userId);
      addAssignment({ accountId: userId, permissionId: roleId, assignmentType: "DIRECT_ROLE" });
    }
  }

  for (const org of snapshot.organizations) {
    const orgId = organizationPermissionId(org.id);
    addPermission({
      permissionId: orgId,
      name: org.displayName || org.name,
      description: `Auth0 organization ${org.name}`,
      type: "ORGANIZATION",
      value: org.id,
      applicationName,
    });
    const seenOrgRoles = new Set<string>();
    const addOrgRole = (member: RawOrgMember, roleId: string, roleName: string): void => {
      const permissionId = organizationRolePermissionId(org.id, roleId);
      if (!seenOrgRoles.has(permissionId)) {
        seenOrgRoles.add(permissionId);
        addPermission({
          permissionId,
          name: `${roleName} @ ${org.displayName || org.name}`,
          description: `Role ${roleName} in organization ${org.displayName || org.name}`,
          type: "ORGANIZATION_ROLE",
          value: roleId,
          applicationName,
        });
        addLink({ parentPermissionId: orgId, childPermissionId: permissionId, relation: "CONTAINS" });
        for (const scopeId of scopeGrantsByRole.get(roleId) ?? []) {
          addLink({ parentPermissionId: permissionId, childPermissionId: scopeId, relation: "GRANTS" });
        }
      }
      addAssignment({
        accountId: member.userId,
        permissionId,
        assignmentType: "ORGANIZATION_ROLE",
      });
    };
    for (const member of org.members) {
      ensureUser(users, member.userId, { email: member.email, name: member.name });
      addAssignment({ accountId: member.userId, permissionId: orgId, assignmentType: "ORGANIZATION_MEMBER" });
      for (const role of member.roles) {
        if (!role.id) continue;
        addOrgRole(member, role.id, role.name || role.id);
      }
    }
  }

  for (const application of snapshot.applications) {
    addPermission({
      permissionId: applicationPermissionId(application.clientId),
      name: application.name,
      description: application.description || `Auth0 application (${application.appType || "unspecified type"})`,
      type: "APPLICATION",
      value: application.clientId,
      applicationName,
    });
  }

  // Groups by connection, so a map entry can find "Billing Admins" on one IdP or on all of them.
  const groupsByValue = new Map<string, { connection: string; permissionId: string }[]>();
  for (const user of users.values()) {
    const connection = firstIdentity(user).connection || "unknown";
    for (const group of user.groups ?? []) {
      const permissionId = groupPermissionId(connection, group.value);
      if (!permissions.has(permissionId)) {
        addPermission({
          permissionId,
          name: group.value,
          description: `Group asserted by connection ${connection} (attribute ${group.attribute})`,
          type: "GROUP",
          value: group.value,
          applicationName,
        });
        const known = groupsByValue.get(group.value) ?? [];
        known.push({ connection, permissionId });
        groupsByValue.set(group.value, known);
      }
      addAssignment({ accountId: user.userId, permissionId, assignmentType: "GROUP_MEMBER" });
    }
  }

  const unmatchedMappings: GroupRoleMapping[] = [];
  const grantedRolesByGroup = new Map<string, string[]>();
  for (const mapping of options.groupRoleMap ?? []) {
    const roles = snapshot.roles.filter((role) => role.id === mapping.role || role.name === mapping.role);
    const groups = (groupsByValue.get(mapping.group) ?? []).filter(
      (group) => !mapping.connection || group.connection === mapping.connection,
    );
    if (roles.length === 0 || groups.length === 0) {
      unmatchedMappings.push(mapping);
      continue;
    }
    for (const group of groups) {
      for (const role of roles) {
        const roleId = rolePermissionId(role.id);
        addLink({ parentPermissionId: group.permissionId, childPermissionId: roleId, relation: "GRANTS" });
        grantedRolesByGroup.set(group.permissionId, [...(grantedRolesByGroup.get(group.permissionId) ?? []), roleId]);
      }
    }
  }

  const accounts = [...users.values()].map(toAccount);
  const privilegedIds = new Set(
    [...permissions.values()]
      .filter((permission) => ["ROLE", "ORGANIZATION_ROLE", "GROUP"].includes(permission.type))
      .filter((permission) => PRIVILEGED_NAME.test(permission.name))
      .map((permission) => permission.permissionId),
  );
  // A group mapped to a privileged role is privileged too, whatever it is called.
  for (const [groupId, roleIds] of grantedRolesByGroup) {
    if (roleIds.some((roleId) => privilegedIds.has(roleId))) privilegedIds.add(groupId);
  }
  for (const account of accounts) {
    account.privileged = [...assignments.values()].some(
      (assignment) => assignment.accountId === account.accountId && privilegedIds.has(assignment.permissionId),
    );
  }

  accounts.sort((left, right) => compare(left.accountId, right.accountId));
  const permissionList = [...permissions.values()].sort((left, right) =>
    compare(left.permissionId, right.permissionId),
  );
  const assignmentList = [...assignments.values()].sort((left, right) => {
    return (
      compare(left.accountId, right.accountId) ||
      compare(left.permissionId, right.permissionId) ||
      compare(left.assignmentType, right.assignmentType)
    );
  });
  const hierarchyList = [...hierarchy.values()].sort((left, right) => {
    return (
      compare(left.parentPermissionId, right.parentPermissionId) ||
      compare(left.childPermissionId, right.childPermissionId) ||
      compare(left.relation, right.relation)
    );
  });

  return {
    accounts,
    permissions: permissionList,
    assignments: assignmentList,
    hierarchy: hierarchyList,
    unmatchedMappings,
  };
}

export function isPrivilegedRoleName(name: string): boolean {
  return PRIVILEGED_NAME.test(name);
}
