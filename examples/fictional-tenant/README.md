# Fictional sample output

These files are **not** an export of a real Auth0 tenant. They were produced by `auth0-iga-exporter` against the in-repo mock Management API (`test/mock-server.ts`). Names, email addresses, role ids, and the domain `tenant.example.auth0.test` are made up. Email addresses use `example.com`.

Regenerate them with:

```bash
npm run generate-sample
```

The mock tenant also plants client secrets, an API signing secret, a connection client secret, and identity-provider tokens. None of those values are present in this directory.
