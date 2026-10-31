const MIN_SECRET_LENGTH = 8;

/**
 * Replace known secret values in text that is about to be printed.
 * Short strings are left alone so values such as "true" are not scrubbed.
 */
export function redact(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length < MIN_SECRET_LENGTH) continue;
    if (!out.includes(secret)) continue;
    out = out.split(secret).join("[redacted]");
  }
  return out;
}
