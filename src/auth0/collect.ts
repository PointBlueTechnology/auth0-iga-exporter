import type { ManagementClient } from "auth0";
import type { Logger } from "../log.js";
import type { ResolvedConfig } from "../config.js";
import type {
  RawApi,
  RawApplication,
  RawConnection,
  RawOrganization,
  RawRole,
  RawSnapshot,
  RawUser,
  UsersSource,
} from "../model/types.js";
import { statusOf } from "./api-error.js";
import { drain } from "./paginate.js";
import {
  toRawApi,
  toRawApplication,
  toRawConnection,
  toRawUser,
  type Auth0ClientRecord,
  type Auth0ConnectionRecord,
  type Auth0ResourceServerRecord,
  type Auth0UserRecord,
} from "./sanitize.js";
import { exportAllUsers } from "./users-export.js";

/** Auth0 refuses to page GET /users past 1,000 records. */
const USER_LIST_CAP = 1000;

/**
 * Drop repeats of the same user (a list page can overlap the next). A user is its
 * user_id plus its primary connection: two database connections can hand out the
 * same user_id to different people, and both have to reach the review.
 */
function dedupeUsers(users: RawUser[]): RawUser[] {
  const seen = new Map<string, RawUser>();
  for (const user of users) {
    const key = `${user.userId}\0${user.identities[0]?.connection ?? ""}`;
    if (!seen.has(key)) seen.set(key, user);
  }
  return [...seen.values()];
}

async function listUsers(
  client: ManagementClient,
  perPage: number,
  groupAttributes: readonly string[],
  log: Logger,
): Promise<RawUser[]> {
  const page = await client.users.list({ page: 0, per_page: perPage, include_totals: true });
  const users: RawUser[] = [];
  for await (const user of page) {
    const raw = toRawUser(user as Auth0UserRecord, groupAttributes);
    if (raw) users.push(raw);
    if (users.length >= USER_LIST_CAP) {
      log.warn(
        "Stopped at 1000 users. GET /api/v2/users cannot page past that ceiling. Re-run with --users-source export for a complete snapshot.",
      );
      break;
    }
  }
  return dedupeUsers(users);
}

async function collectUsers(
  client: ManagementClient,
  config: ResolvedConfig,
  log: Logger,
): Promise<{ users: RawUser[]; source: UsersSource }> {
  if (config.usersSource === "export") {
    log.info("collecting users with the bulk export job");
    const users = dedupeUsers(
      await exportAllUsers(client, {
        pollMs: config.jobPollMs,
        maxPolls: config.jobPollAttempts,
        groupAttributes: config.groupAttributes,
      }),
    );
    return { users, source: "export" };
  }
  if (config.usersSource === "list") {
    log.info("collecting users with GET /api/v2/users");
    return { users: await listUsers(client, config.perPage, config.groupAttributes, log), source: "list" };
  }

  const probe = await client.users.list({ page: 0, per_page: 1, include_totals: true });
  const total = probe.response.total;
  if (typeof total === "number" && total >= config.exportThreshold) {
    log.info(
      `reported user total ${total} reached the export threshold (${config.exportThreshold}); using the bulk export job`,
    );
    const users = dedupeUsers(
      await exportAllUsers(client, {
        pollMs: config.jobPollMs,
        maxPolls: config.jobPollAttempts,
        groupAttributes: config.groupAttributes,
      }),
    );
    return { users, source: "export" };
  }
  log.info("collecting users with GET /api/v2/users");
  return { users: await listUsers(client, config.perPage, config.groupAttributes, log), source: "list" };
}

async function collectRoles(client: ManagementClient, perPage: number): Promise<RawRole[]> {
  const roles = await drain(await client.roles.list({ page: 0, per_page: perPage, include_totals: true }));
  const collected: RawRole[] = [];
  for (const role of roles) {
    if (!role.id) continue;
    const permissions = await drain(
      await client.roles.permissions.list(role.id, { page: 0, per_page: perPage, include_totals: true }),
    );
    const members = await drain(await client.roles.users.list(role.id, { take: perPage }));
    collected.push({
      id: role.id,
      name: role.name ?? role.id,
      description: role.description ?? "",
      permissions: permissions.flatMap((permission) => {
        if (!permission.permission_name) return [];
        return [
          {
            permissionName: permission.permission_name,
            resourceServerIdentifier: permission.resource_server_identifier,
            resourceServerName: permission.resource_server_name,
            description: permission.description,
          },
        ];
      }),
      userIds: [...new Set(members.flatMap((member) => (member.user_id ? [member.user_id] : [])))],
    });
  }
  return collected;
}

async function collectOrganizations(client: ManagementClient, perPage: number): Promise<RawOrganization[]> {
  const organizations = await drain(await client.organizations.list({ take: perPage }));
  const collected: RawOrganization[] = [];
  for (const org of organizations) {
    if (!org.id) continue;
    const members = await drain(
      await client.organizations.members.list(org.id, {
        take: perPage,
        fields: "user_id,email,name,roles",
        include_fields: true,
      }),
    );
    const rawMembers = [];
    for (const member of members) {
      if (!member.user_id) continue;
      let roles = member.roles;
      if (roles === undefined) {
        const listed = await drain(
          await client.organizations.members.roles.list(org.id, member.user_id, {
            page: 0,
            per_page: perPage,
            include_totals: true,
          }),
        );
        roles = listed.map((role) => ({ id: role.id, name: role.name }));
      }
      rawMembers.push({
        userId: member.user_id,
        email: member.email,
        name: member.name,
        roles: roles.flatMap((role) => (role.id ? [{ id: role.id, name: role.name ?? role.id }] : [])),
      });
    }
    collected.push({
      id: org.id,
      name: org.name ?? org.id,
      displayName: org.display_name ?? org.name ?? org.id,
      members: rawMembers,
    });
  }
  return collected;
}

async function collectApplications(client: ManagementClient, perPage: number): Promise<RawApplication[]> {
  const clients = await drain(
    await client.clients.list({
      page: 0,
      per_page: perPage,
      include_totals: true,
      fields: "client_id,name,app_type,description",
      include_fields: true,
    }),
  );
  return clients.flatMap((clientRecord) => {
    const application = toRawApplication(clientRecord as Auth0ClientRecord);
    return application ? [application] : [];
  });
}

async function collectApis(client: ManagementClient, perPage: number): Promise<RawApi[]> {
  const servers = await drain(
    await client.resourceServers.list({ page: 0, per_page: perPage, include_totals: true }),
  );
  return servers.flatMap((server) => {
    const api = toRawApi(server as Auth0ResourceServerRecord);
    return api ? [api] : [];
  });
}

async function collectConnections(client: ManagementClient, perPage: number, log: Logger): Promise<RawConnection[]> {
  try {
    const connections = await drain(await client.connections.list({ take: perPage }));
    return connections.flatMap((connection) => {
      const raw = toRawConnection(connection as Auth0ConnectionRecord);
      return raw ? [raw] : [];
    });
  } catch (err) {
    if (statusOf(err) === 403) {
      log.warn("Skipping the connection catalog (403). Grant read:connections to include it.");
      return [];
    }
    throw err;
  }
}

export async function collectSnapshot(
  client: ManagementClient,
  config: ResolvedConfig,
  log: Logger,
): Promise<RawSnapshot> {
  const { users, source } = await collectUsers(client, config, log);
  log.info(`collected ${users.length} users via ${source}`);

  log.info("collecting roles, role permissions, and direct role members");
  const roles = await collectRoles(client, config.perPage);
  log.info(`collected ${roles.length} roles`);

  log.info("collecting organizations and members");
  const organizations = await collectOrganizations(client, config.perPage);
  log.info(`collected ${organizations.length} organizations`);

  log.info("collecting applications");
  const applications = await collectApplications(client, config.perPage);
  log.info(`collected ${applications.length} applications`);

  log.info("collecting APIs");
  const resourceServers = await collectApis(client, config.perPage);
  log.info(`collected ${resourceServers.length} APIs`);

  const connections = await collectConnections(client, config.perPage, log);
  log.info(`collected ${connections.length} connections`);

  return {
    domain: config.domain,
    applicationName: config.applicationName,
    usersSource: source,
    collectedAt: new Date().toISOString(),
    users,
    roles,
    organizations,
    applications,
    resourceServers,
    connections,
  };
}
