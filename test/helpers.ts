import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CLIENT_ID, CLIENT_SECRET, TENANT_DOMAIN } from "./fixture.js";

export const repoRoot = fileURLToPath(new URL("..", import.meta.url));

export function childEnv(overrides: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("AUTH0_")) delete env[key];
  }
  return { ...env, ...overrides };
}

export function credentialEnv(baseUrl: string, overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  return childEnv({
    AUTH0_DOMAIN: TENANT_DOMAIN,
    AUTH0_CLIENT_ID: CLIENT_ID,
    AUTH0_CLIENT_SECRET: CLIENT_SECRET,
    AUTH0_BASE_URL: baseUrl,
    ...overrides,
  });
}

export function runCli(
  args: string[],
  env: NodeJS.ProcessEnv,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: repoRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

export async function tempDir(): Promise<{ dir: string; remove: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), "auth0-iga-"));
  return { dir, remove: () => rm(dir, { recursive: true, force: true }) };
}
