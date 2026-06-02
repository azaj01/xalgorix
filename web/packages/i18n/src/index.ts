/**
 * `@xalgorix/i18n` — next-intl catalogs + missing-key logger.
 *
 * Per design.md § "i18n" and Requirement 18.7, missing keys must be reported
 * to the API_Server at `/api/internal/observability/i18n_missing`. The logger
 * lives here so all three Next.js apps share a single integration point.
 */

export const SUPPORTED_LOCALES = ["en"] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export interface MissingKeyEvent {
  locale: Locale;
  namespace: string;
  key: string;
  fallback?: string;
}

/**
 * Posts a missing-key event to the API_Server. The endpoint will be wired in
 * Phase 18; at bootstrap time we ship a no-op-on-failure implementation so the
 * shell renders even when the API is unreachable.
 */
export async function reportMissingKey(
  event: MissingKeyEvent,
  endpoint = "/api/internal/observability/i18n_missing",
): Promise<void> {
  if (typeof fetch === "undefined") {
    return;
  }
  try {
    await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(event),
      keepalive: true,
    });
  } catch {
    // Intentionally swallow — observability must never break the UI.
  }
}
