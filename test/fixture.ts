/** Fictional Auth0 tenant used by the mock Management API. Not a real customer. */

export const TENANT_DOMAIN = "tenant.example.auth0.test";
export const CLIENT_ID = "test-client-id";
export const CLIENT_SECRET = "test-client-secret-value";

export const SECRET_CLIENT = "spa-client-secret-value";
export const SECRET_SIGNING = "api-signing-secret-value";
export const SECRET_CONNECTION = "connection-options-secret-value";
export const SECRET_IDP_ACCESS = "idp-access-token-value";
export const SECRET_IDP_REFRESH = "idp-refresh-token-value";
export const DECOY_EMAIL = "decoy.list@example.com";

export const APPLICATION_NAME = "Fictional Northwind tenant";

const users = [
  {
    user_id: "auth0|avery",
    email: "avery.chen@example.com",
    email_verified: true,
    username: "avery.chen",
    name: "Chen, Avery",
    given_name: "Avery",
    family_name: "Chen",
    nickname: "avery",
    created_at: "2024-01-15T10:00:00.000Z",
    updated_at: "2026-04-01T12:00:00.000Z",
    last_login: "2026-04-30T15:04:00.000Z",
    logins_count: 42,
    blocked: false,
    identities: [
      {
        provider: "auth0",
        connection: "Username-Password-Authentication",
        user_id: "avery",
        isSocial: false,
      },
    ],
  },
  {
    user_id: "auth0|jordan",
    email: "jordan.blake@example.com",
    email_verified: true,
    name: "Jordan Blake",
    given_name: "Jordan",
    family_name: "Blake",
    created_at: "2023-06-01T08:00:00.000Z",
    updated_at: "2025-11-02T08:00:00.000Z",
    last_login: "2025-11-02T08:00:00.000Z",
    logins_count: 3,
    blocked: true,
    identities: [
      {
        provider: "auth0",
        connection: "Username-Password-Authentication",
        user_id: "jordan",
        isSocial: false,
      },
    ],
  },
  {
    user_id: "google-oauth2|samir",
    email: "samir.okonkwo@example.com",
    email_verified: true,
    name: "Samir Okonkwo",
    given_name: "Samir",
    family_name: "Okonkwo",
    created_at: "2025-02-11T16:30:00.000Z",
    updated_at: "2026-03-20T09:12:00.000Z",
    identities: [
      {
        provider: "google-oauth2",
        connection: "google-oauth2",
        user_id: "samir",
        isSocial: true,
        access_token: SECRET_IDP_ACCESS,
        refresh_token: SECRET_IDP_REFRESH,
      },
    ],
  },
];

export interface Fixture {
  users: typeof users;
  roles: Array<{ id: string; name: string; description: string }>;
  rolePermissions: Record<
    string,
    Array<{
      permission_name: string;
      resource_server_identifier: string;
      resource_server_name: string;
      description: string;
    }>
  >;
  roleUsers: Record<string, Array<{ user_id: string; email: string; name: string }>>;
  organizations: Array<{ id: string; name: string; display_name: string }>;
  members: Record<
    string,
    Array<{ user_id: string; email: string; name: string; roles?: Array<{ id: string; name: string }> }>
  >;
  clients: Array<Record<string, unknown>>;
  resourceServers: Array<Record<string, unknown>>;
  connections: Array<Record<string, unknown>>;
}

export function fictionalTenant(): Fixture {
  return {
    users: structuredClone(users),
    roles: [
      { id: "rol_billingadmin", name: "Billing Admin", description: "Manage invoices" },
      { id: "rol_viewer", name: "Invoice Viewer", description: "Read invoices" },
    ],
    rolePermissions: {
      rol_billingadmin: [
        {
          permission_name: "read:invoices",
          resource_server_identifier: "https://invoices.example.com",
          resource_server_name: "Invoices API",
          description: "Read invoices",
        },
        {
          permission_name: "write:invoices",
          resource_server_identifier: "https://invoices.example.com",
          resource_server_name: "Invoices API",
          description: "Create and update invoices",
        },
      ],
      rol_viewer: [
        {
          permission_name: "read:invoices",
          resource_server_identifier: "https://invoices.example.com",
          resource_server_name: "Invoices API",
          description: "Read invoices",
        },
      ],
    },
    roleUsers: {
      rol_billingadmin: [
        { user_id: "auth0|avery", email: "avery.chen@example.com", name: "Chen, Avery" },
      ],
      rol_viewer: [
        { user_id: "auth0|jordan", email: "jordan.blake@example.com", name: "Jordan Blake" },
      ],
    },
    organizations: [
      { id: "org_northwind", name: "northwind", display_name: "Northwind Traders" },
      { id: "org_contoso", name: "contoso", display_name: "Contoso Ltd" },
    ],
    members: {
      org_northwind: [
        {
          user_id: "auth0|avery",
          email: "avery.chen@example.com",
          name: "Chen, Avery",
          roles: [{ id: "rol_viewer", name: "Invoice Viewer" }],
        },
        {
          user_id: "google-oauth2|samir",
          email: "samir.okonkwo@example.com",
          name: "Samir Okonkwo",
          roles: [],
        },
      ],
      org_contoso: [],
    },
    clients: [
      {
        client_id: "spaNorthwindPortal",
        name: "Northwind Portal",
        app_type: "spa",
        description: "Employee portal",
        client_secret: SECRET_CLIENT,
      },
      {
        client_id: "m2mNightlySync",
        name: "Nightly Sync",
        app_type: "non_interactive",
        description: "Machine-to-machine sync",
        client_secret: SECRET_CLIENT,
      },
    ],
    resourceServers: [
      {
        id: "rs_invoices",
        name: "Invoices API",
        identifier: "https://invoices.example.com",
        is_system: false,
        signing_secret: SECRET_SIGNING,
        scopes: [
          { value: "read:invoices", description: "Read invoices" },
          { value: "write:invoices", description: "Create and update invoices" },
        ],
      },
      {
        id: "rs_directory",
        name: "Partner Directory",
        identifier: "https://directory.example.com",
        is_system: false,
        signing_secret: SECRET_SIGNING,
        scopes: [{ value: "read:partners", description: "Read partner records" }],
      },
    ],
    connections: [
      {
        id: "con_DbUsers00000001",
        name: "Username-Password-Authentication",
        strategy: "auth0",
        display_name: "Database",
        options: { client_secret: SECRET_CONNECTION },
      },
      {
        id: "con_Google000000001",
        name: "google-oauth2",
        strategy: "google-oauth2",
        display_name: "Google",
        options: { client_secret: SECRET_CONNECTION },
      },
    ],
  };
}

export function decoyUser(): Fixture["users"][number] {
  return {
    user_id: "auth0|decoy",
    email: DECOY_EMAIL,
    email_verified: false,
    name: "List Decoy",
    created_at: "2026-01-01T00:00:00.000Z",
    updated_at: "2026-01-01T00:00:00.000Z",
    blocked: false,
    identities: [
      {
        provider: "auth0",
        connection: "Username-Password-Authentication",
        user_id: "decoy",
        isSocial: false,
      },
    ],
  };
}
