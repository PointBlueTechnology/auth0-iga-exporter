import { applicationRecordId } from "../model/ids.js";
import type { IgBundle, NormalizedExport, RawSnapshot } from "../model/types.js";
import { VERSION } from "../version.js";

export function toBundle(snapshot: RawSnapshot, normalized: NormalizedExport): IgBundle {
  return {
    schema: "pointblue.auth0-iga-exporter/v0.1",
    generator: `auth0-iga-exporter ${VERSION}`,
    meta: {
      exportedAt: snapshot.collectedAt,
      domain: snapshot.domain,
      applicationName: snapshot.applicationName,
      usersSource: snapshot.usersSource,
    },
    application: {
      id: applicationRecordId(snapshot.domain),
      name: snapshot.applicationName,
      type: "Auth0",
      description: "Auth0 tenant exported for identity governance access reviews",
    },
    accounts: normalized.accounts,
    permissions: normalized.permissions,
    assignments: normalized.assignments,
    permissionHierarchy: normalized.hierarchy,
    catalog: {
      roles: snapshot.roles,
      organizations: snapshot.organizations,
      applications: snapshot.applications,
      resourceServers: snapshot.resourceServers,
      connections: snapshot.connections,
    },
  };
}
