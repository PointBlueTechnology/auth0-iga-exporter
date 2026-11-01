export const PERMISSION_TYPES = [
  "ROLE",
  "API",
  "API_SCOPE",
  "ORGANIZATION",
  "ORGANIZATION_ROLE",
  "APPLICATION",
  "GROUP",
] as const;

export type PermissionType = (typeof PERMISSION_TYPES)[number];

/** How the account signs in, from its primary identity. */
export type AccountSource = "DATABASE" | "SOCIAL" | "ENTERPRISE" | "PASSWORDLESS" | "UNKNOWN";

export type AssignmentType = "DIRECT_ROLE" | "ORGANIZATION_MEMBER" | "ORGANIZATION_ROLE" | "GROUP_MEMBER";

export type HierarchyRelation = "GRANTS" | "CONTAINS";

export type UsersSource = "list" | "export";

export interface RawIdentity {
  provider: string;
  connection: string;
  userId: string;
  isSocial?: boolean;
}

/** One value of a configured group attribute, such as `groups` from a SAML or Azure AD connection. */
export interface RawUserGroup {
  attribute: string;
  value: string;
}

/** Maps an identity-provider group to the Auth0 role it is meant to grant. */
export interface GroupRoleMapping {
  /** Connection name. Omitted means the group on any connection. */
  connection?: string;
  group: string;
  /** Role id or role name. */
  role: string;
}

export interface RawUser {
  userId: string;
  email?: string;
  emailVerified?: boolean;
  username?: string;
  name?: string;
  nickname?: string;
  givenName?: string;
  familyName?: string;
  createdAt?: string;
  updatedAt?: string;
  lastLogin?: string;
  loginsCount?: number;
  blocked: boolean;
  identities: RawIdentity[];
  groups?: RawUserGroup[];
}

export interface RawRolePermission {
  permissionName: string;
  resourceServerIdentifier?: string;
  resourceServerName?: string;
  description?: string;
}

export interface RawRole {
  id: string;
  name: string;
  description: string;
  permissions: RawRolePermission[];
  userIds: string[];
}

export interface RawOrgRole {
  id: string;
  name: string;
}

export interface RawOrgMember {
  userId: string;
  email?: string;
  name?: string;
  roles: RawOrgRole[];
}

export interface RawOrganization {
  id: string;
  name: string;
  displayName: string;
  members: RawOrgMember[];
}

export interface RawApplication {
  clientId: string;
  name: string;
  appType: string;
  description: string;
}

export interface RawApiScope {
  value: string;
  description: string;
}

export interface RawApi {
  id: string;
  name: string;
  identifier: string;
  isSystem: boolean;
  scopes: RawApiScope[];
}

export interface RawConnection {
  id: string;
  name: string;
  strategy: string;
  displayName: string;
}

export interface RawSnapshot {
  domain: string;
  applicationName: string;
  usersSource: UsersSource;
  collectedAt: string;
  users: RawUser[];
  roles: RawRole[];
  organizations: RawOrganization[];
  applications: RawApplication[];
  resourceServers: RawApi[];
  connections: RawConnection[];
}

export interface IgAccount {
  accountId: string;
  name: string;
  displayName: string;
  description: string;
  email: string;
  username: string;
  idmAccountId: string;
  disabled: boolean;
  lastLogin: string;
  privileged: boolean;
  status: "ACTIVE" | "BLOCKED";
  connection: string;
  provider: string;
  identities: RawIdentity[];
  createdAt: string;
  updatedAt: string;
  loginsCount: number | null;
  emailVerified: boolean | null;
  givenName: string;
  familyName: string;
  /** The Auth0 user_id. Equal to accountId unless two connections share the user_id. */
  userId: string;
  accountSource: AccountSource;
}

export interface IgPermission {
  permissionId: string;
  name: string;
  description: string;
  type: PermissionType;
  value: string;
  applicationName: string;
}

export interface IgAssignment {
  accountId: string;
  permissionId: string;
  assignmentType: AssignmentType;
}

export interface IgHierarchy {
  parentPermissionId: string;
  childPermissionId: string;
  relation: HierarchyRelation;
}

export interface NormalizedExport {
  accounts: IgAccount[];
  permissions: IgPermission[];
  assignments: IgAssignment[];
  hierarchy: IgHierarchy[];
  /** Group-to-role mappings that matched no exported group or no role. */
  unmatchedMappings: GroupRoleMapping[];
  /** user_ids held by users on more than one connection, with the account ids they became. */
  sharedUserIds: Array<{ userId: string; accountIds: string[] }>;
}

export interface IgBundle {
  schema: "pointblue.auth0-iga-exporter/v0.1";
  generator: string;
  meta: {
    exportedAt: string;
    domain: string;
    applicationName: string;
    usersSource: UsersSource;
  };
  application: {
    id: string;
    name: string;
    type: "Auth0";
    description: string;
  };
  accounts: IgAccount[];
  permissions: IgPermission[];
  assignments: IgAssignment[];
  permissionHierarchy: IgHierarchy[];
  catalog: {
    roles: RawRole[];
    organizations: RawOrganization[];
    applications: RawApplication[];
    resourceServers: RawApi[];
    connections: RawConnection[];
  };
}
