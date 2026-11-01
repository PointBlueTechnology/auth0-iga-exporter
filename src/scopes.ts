/**
 * Minimum read-only Management API scopes for a full export.
 * Do not grant create, update, or delete scopes. Do not grant
 * read:user_idp_tokens — identity-provider tokens are not part of an access review
 * and are discarded if a payload contains them anyway.
 */
export interface ScopeRequirement {
  scope: string;
  required: boolean;
  purpose: string;
}

export const SCOPE_REQUIREMENTS: ScopeRequirement[] = [
  {
    scope: "read:users",
    required: true,
    purpose: "List users, probe the user total, and run the bulk user export job.",
  },
  {
    scope: "read:roles",
    required: true,
    purpose: "List roles, the permissions on each role, and (with read:users) users directly assigned to a role.",
  },
  {
    scope: "read:organizations",
    required: true,
    purpose: "List organizations.",
  },
  {
    scope: "read:organization_members",
    required: true,
    purpose: "List members of each organization.",
  },
  {
    scope: "read:organization_member_roles",
    required: true,
    purpose: "List roles an organization member holds when the member payload does not already include them.",
  },
  {
    scope: "read:clients",
    required: true,
    purpose: "List applications. Client secrets are dropped and never written.",
  },
  {
    scope: "read:resource_servers",
    required: true,
    purpose: "List APIs and their scopes. Signing secrets are dropped and never written.",
  },
  {
    scope: "read:connections",
    required: false,
    purpose:
      "Connection catalog (id, name, strategy). A 403 skips the catalog. The user export itself does not need this scope.",
  },
];

export const REQUIRED_SCOPES = SCOPE_REQUIREMENTS.filter((item) => item.required).map((item) => item.scope);

export function formatScopesText(): string {
  const lines = [
    "Auth0 Management API scopes for the machine-to-machine application.",
    "Authorize the app for the Auth0 Management API audience https://<domain>/api/v2/",
    "",
    "Required:",
  ];
  for (const item of SCOPE_REQUIREMENTS.filter((entry) => entry.required)) {
    lines.push(`  ${item.scope}`);
    lines.push(`    ${item.purpose}`);
  }
  lines.push("");
  lines.push("Optional:");
  for (const item of SCOPE_REQUIREMENTS.filter((entry) => !entry.required)) {
    lines.push(`  ${item.scope}`);
    lines.push(`    ${item.purpose}`);
  }
  lines.push("");
  lines.push("Do not grant: create:*, update:*, delete:*, read:user_idp_tokens, read:client_keys.");
  lines.push("");
  lines.push(`Comma-separated required scopes:`);
  lines.push(`  ${REQUIRED_SCOPES.join(",")}`);
  return lines.join("\n");
}
