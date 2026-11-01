export function rolePermissionId(roleId: string): string {
  return `role:${roleId}`;
}

export function apiPermissionId(identifier: string): string {
  return `api:${identifier}`;
}

export function scopePermissionId(identifier: string, permissionName: string): string {
  return `scope:${identifier}::${permissionName}`;
}

export function organizationPermissionId(orgId: string): string {
  return `organization:${orgId}`;
}

export function organizationRolePermissionId(orgId: string, roleId: string): string {
  return `organization-role:${orgId}:${roleId}`;
}

export function applicationPermissionId(clientId: string): string {
  return `application:${clientId}`;
}

/** Groups are scoped to the connection that asserted them: two IdPs can both send "Admins". */
export function groupPermissionId(connection: string, value: string): string {
  return `group:${connection}::${value}`;
}

export function applicationRecordId(domain: string): string {
  return `auth0:${domain}`;
}
