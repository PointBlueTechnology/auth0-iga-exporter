import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/cli.ts";
import { APPLICATION_NAME, CLIENT_ID, CLIENT_SECRET, TENANT_DOMAIN } from "../test/fixture.ts";
import { startMock } from "../test/mock-server.ts";

const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const out = join(repoRoot, "examples", "fictional-tenant");

const mock = await startMock();
const previous = {
  domain: process.env.AUTH0_DOMAIN,
  clientId: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  baseUrl: process.env.AUTH0_BASE_URL,
};
process.env.AUTH0_DOMAIN = TENANT_DOMAIN;
process.env.AUTH0_CLIENT_ID = CLIENT_ID;
process.env.AUTH0_CLIENT_SECRET = CLIENT_SECRET;
process.env.AUTH0_BASE_URL = mock.baseUrl;

try {
  const code = await run([
    "export",
    "--out",
    out,
    "--format",
    "all",
    "--users-source",
    "list",
    "--per-page",
    "50",
    "--application-name",
    APPLICATION_NAME,
  ]);
  if (code !== 0) {
    throw new Error(`sample export failed with exit ${code}`);
  }
} finally {
  await mock.close();
  if (previous.domain === undefined) delete process.env.AUTH0_DOMAIN;
  else process.env.AUTH0_DOMAIN = previous.domain;
  if (previous.clientId === undefined) delete process.env.AUTH0_CLIENT_ID;
  else process.env.AUTH0_CLIENT_ID = previous.clientId;
  if (previous.clientSecret === undefined) delete process.env.AUTH0_CLIENT_SECRET;
  else process.env.AUTH0_CLIENT_SECRET = previous.clientSecret;
  if (previous.baseUrl === undefined) delete process.env.AUTH0_BASE_URL;
  else process.env.AUTH0_BASE_URL = previous.baseUrl;
}

console.log(`wrote fictional sample to ${out}`);
