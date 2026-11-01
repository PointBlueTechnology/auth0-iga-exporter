# Changelog

## 0.2.0 (2026-11-01)

The first run against a real tenant (175 users) drove this release.

### Added

- **SSO groups.** Groups an enterprise connection asserts at sign-in become `GROUP` permissions, scoped to the connection (`group:<connection>::<value>`), with `GROUP_MEMBER` assignments and SCIM groups.
  - `--group-attributes` names the attributes to read: root attributes or `app_metadata` paths. The default is `groups,group_ids`. `user_metadata` is refused because the user can edit it.
  - `--group-role-map` links a group to the Auth0 role it is meant to grant, as a `GRANTS` link in the hierarchy. It never adds a role assignment.
  - Tested live against a SAML connection.
- `--include-system-scopes`, to emit every Management API scope.
- Account columns `userId` (the raw Auth0 `user_id`) and `accountSource` (`DATABASE`, `SOCIAL`, `ENTERPRISE`, `PASSWORDLESS` or `UNKNOWN`).

### Changed

- Management API scopes are emitted only when a role grants them. On the real tenant they had been 281 of 318 permission rows. The bundle catalog still lists every scope.
- `emailVerified` is `false`, not empty, when Auth0 omits `email_verified` on an account that has an email.
- `privileged` also covers plural names ("Billing Admins"), SSO groups, and groups mapped to a privileged role.

### Fixed

- Two database connections can give different users the same `user_id`. One of them was silently dropped. Both are now exported, as `<user_id>@<connection>`, with a warning. Role and organization assignments on that `user_id` go to both accounts.

The bundle schema stays `pointblue.auth0-iga-exporter/v0.1`. Every change to it adds a type or a field; nothing was removed or renamed.

## 0.1.0

First version: accounts, roles, role permissions, organizations, applications, APIs and connections, written as OpenText Identity Governance CSV, a JSON bundle, and SCIM 2.0.
