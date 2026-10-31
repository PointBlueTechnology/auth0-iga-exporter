import { redact } from "./redact.js";

export interface Logger {
  info(message: string): void;
  warn(message: string): void;
}

export function createLogger(secrets: readonly string[]): Logger {
  return {
    info(message: string): void {
      console.error(redact(message, secrets));
    },
    warn(message: string): void {
      console.error(`warning: ${redact(message, secrets)}`);
    },
  };
}
