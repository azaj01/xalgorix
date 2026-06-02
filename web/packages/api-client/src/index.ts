/**
 * `@xalgorix/api-client` — generated TypeScript client for the Cloud_Platform
 * REST API. Per design.md § "Frontend modules", this package mirrors the
 * OpenAPI 3.1 document served at `/api/v1/openapi.json`.
 *
 * Codegen is wired in Phase 8 / task 8.2. Until then, this file exposes a
 * minimal placeholder so the workspace links and typechecks cleanly.
 */

/** Base URL resolution helper. Apps inject `NEXT_PUBLIC_API_BASE_URL`. */
export function resolveApiBaseUrl(env?: Record<string, string | undefined>): string {
  const source = env ?? (typeof process !== "undefined" ? process.env : {});
  return source.NEXT_PUBLIC_API_BASE_URL ?? "https://api.xalgorix.com/v1";
}

export const API_VERSION = "v1" as const;
