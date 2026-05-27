import type {
  AuthProfile,
  AuthStatus,
  AgentMailSettings,
  CatalogEntry,
  EnvironmentSettings,
  InstancesResponse,
  LLMSettings,
  OAuthStartResponse,
  OpenclawImportResponse,
  QueueStatus,
  RateLimitSettings,
  ScanInstance,
  ScanListItem,
  ScanRecord,
  ScanRequest,
  ScanSchedule,
  StatusResponse,
  VersionInfo,
  WSEvent,
} from "@/types/api";

// Auth session expiry handling. When any API call returns 401 we dispatch a
// global event so the auth store (in store/auth.ts) can flip the user back
// to the login screen without each component having to handle it.
// We avoid importing the store directly to keep this module free of
// circular deps with the rest of the app.
const AUTH_EXPIRED_EVENT = "xalgorix:auth-expired";
let lastAuthExpiredDispatch = 0;

function dispatchAuthExpired() {
  // Debounce: when multiple SWR keys fail at once we'd otherwise fire
  // dozens of events in a single tick.
  const now = Date.now();
  if (now - lastAuthExpiredDispatch < 1000) return;
  lastAuthExpiredDispatch = now;
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
  }
}

export const AUTH_EXPIRED = AUTH_EXPIRED_EVENT;

/**
 * Structured HTTP error thrown by `http()`. Carries the status code, the
 * raw response body, and any JSON-decoded body so callers (login form,
 * settings, etc.) can render a friendly message instead of leaking the
 * raw `HTTP 401 Unauthorized: {"error":"…"}` envelope into the UI.
 */
export class HttpError extends Error {
  status: number;
  statusText: string;
  body: string;
  data: unknown;
  retryAfter?: number;
  constructor(opts: {
    status: number;
    statusText: string;
    body: string;
    data: unknown;
    retryAfter?: number;
  }) {
    // `message` stays useful for unhandled-error toasts / console logs, but
    // UI code should branch on `.status` and use `.data?.error` when it
    // wants a polished string.
    const fromData =
      opts.data &&
      typeof opts.data === "object" &&
      "error" in (opts.data as Record<string, unknown>)
        ? String((opts.data as { error?: unknown }).error ?? "")
        : "";
    const detail = fromData || opts.body;
    super(
      `HTTP ${opts.status}${opts.statusText ? ` ${opts.statusText}` : ""}${
        detail ? `: ${detail}` : ""
      }`,
    );
    this.name = "HttpError";
    this.status = opts.status;
    this.statusText = opts.statusText;
    this.body = opts.body;
    this.data = opts.data;
    this.retryAfter = opts.retryAfter;
  }
}

async function http<T>(
  path: string,
  init?: RequestInit & { json?: unknown },
): Promise<T> {
  const headers: HeadersInit = {
    Accept: "application/json",
    ...(init?.headers || {}),
  };
  let body = init?.body;
  if (init?.json !== undefined) {
    body = JSON.stringify(init.json);
    (headers as Record<string, string>)["Content-Type"] = "application/json";
  }
  let res: Response;
  try {
    res = await fetch(path, {
      credentials: "same-origin",
      ...init,
      headers,
      body,
    });
  } catch (err) {
    // Network-level failure: server unreachable, DNS, CORS, abort. Surface
    // it as an HttpError with status 0 so callers can distinguish it from
    // a real HTTP response.
    throw new HttpError({
      status: 0,
      statusText: "Network error",
      body: err instanceof Error ? err.message : String(err),
      data: null,
    });
  }

  if (!res.ok) {
    // Surface session expiry / auth failure to the rest of the app, but
    // never on the login endpoint itself (that 401 is just "bad password"
    // and the form already shows the error inline).
    if (res.status === 401 && path !== "/api/auth/login") {
      dispatchAuthExpired();
    }
    let rawBody = "";
    try {
      rawBody = await res.text();
    } catch {
      /* ignore */
    }
    let parsed: unknown = null;
    if (rawBody) {
      try {
        parsed = JSON.parse(rawBody);
      } catch {
        /* not JSON, leave as null */
      }
    }
    const retryHeader = res.headers.get("Retry-After");
    const retryAfter = retryHeader ? Number(retryHeader) : undefined;
    throw new HttpError({
      status: res.status,
      statusText: res.statusText,
      body: rawBody,
      data: parsed,
      retryAfter: Number.isFinite(retryAfter) ? retryAfter : undefined,
    });
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

export const api = {
  authStatus: () => http<AuthStatus>("/api/auth/status"),
  login: (username: string, password: string) =>
    http<{ status: string }>("/api/auth/login", {
      method: "POST",
      json: { username, password },
    }),
  logout: () =>
    http<{ status: string }>("/api/auth/logout", { method: "POST" }),

  status: () => http<StatusResponse>("/api/status"),
  version: () => http<VersionInfo>("/api/version"),
  listScans: () => http<ScanListItem[] | null>("/api/scans"),
  getScan: (id: string) => http<ScanRecord | null>(`/api/scans/${id}`),
  deleteScan: (id: string) =>
    http<{ status: string }>(`/api/scans/${id}`, { method: "DELETE" }),
  deleteVuln: (scanId: string, vulnId: string) =>
    http<{ status: string; removed: number; remaining: number }>(
      `/api/scans/${scanId}/vulns/${vulnId}`,
      { method: "DELETE" },
    ),

  instances: () => http<InstancesResponse>("/api/instances"),
  instance: (id: string) => http<ScanInstance>(`/api/instances/${id}`),
  instanceEvents: (id: string) =>
    http<WSEvent[]>(`/api/instances/${id}/events`),
  stopInstance: (id: string) =>
    http<{ status: string }>(`/api/instances/${id}/stop`, { method: "POST" }),
  restartInstance: (id: string) =>
    http<{ status: string }>(`/api/instances/${id}/restart`, {
      method: "POST",
    }),
  startSavedInstance: (id: string) =>
    http<{ status: string; instance_id?: string }>(
      `/api/instances/${id}/start`,
      { method: "POST" },
    ),

  startScan: (req: ScanRequest) =>
    http<{ status: string; instance_id: string }>("/api/scan", {
      method: "POST",
      json: req,
    }),
  uploadLogo: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    return http<{ path: string; filename: string }>("/api/upload-logo", {
      method: "POST",
      body,
    });
  },
  stopAll: () => http<{ status: string }>("/api/stop", { method: "POST" }),

  queueStatus: () => http<QueueStatus>("/api/queue/status"),
  queueResume: () =>
    http<{
      status: string;
      resumed_queues?: number;
      from_index?: number;
      targets_left?: number;
      error?: string;
    }>("/api/queue/resume", { method: "POST" }),
  queueClear: () =>
    http<{ status: string }>("/api/queue/clear", { method: "POST" }),

  rateLimit: () => http<RateLimitSettings>("/api/settings/rate-limit"),
  updateRateLimit: (req: RateLimitSettings) =>
    http<RateLimitSettings>("/api/settings/rate-limit", {
      method: "POST",
      json: req,
    }),

  agentMail: () => http<AgentMailSettings>("/api/settings/agentmail"),
  updateAgentMail: (req: { pod: string; apiKey: string }) =>
    http<AgentMailSettings>("/api/settings/agentmail", {
      method: "POST",
      json: req,
    }),

  llmSettings: () => http<LLMSettings>("/api/settings/llm"),
  updateLLMSettings: (req: LLMSettings) =>
    http<LLMSettings>("/api/settings/llm", {
      method: "POST",
      json: req,
    }),

  environmentSettings: () =>
    http<EnvironmentSettings>("/api/settings/environment"),
  updateEnvironmentSettings: (values: Record<string, string>) =>
    http<EnvironmentSettings>("/api/settings/environment", {
      method: "POST",
      json: { values },
    }),

  reportUrl: (scanId: string) => `/api/report/${scanId}`,

  legacyImportStatus: () =>
    http<{ count: number; dismissed: boolean }>("/api/legacy-import/status"),
  dismissLegacyImport: () =>
    http<{ count: number; dismissed: boolean }>(
      "/api/legacy-import/status",
      { method: "POST" },
    ),

  chat: (message: string, instanceId?: string) =>
    http<{ reply?: string; error?: string }>("/api/chat", {
      method: "POST",
      json: { message, instance_id: instanceId },
    }),

  listSchedules: () => http<ScanSchedule[]>("/api/schedules"),
  createSchedule: (schedule: Omit<ScanSchedule, "id" | "next_run">) =>
    http<ScanSchedule>("/api/schedules", {
      method: "POST",
      json: schedule,
    }),
  updateSchedule: (id: string, schedule: Partial<ScanSchedule>) =>
    http<ScanSchedule>(`/api/schedules/${id}`, {
      method: "PUT",
      json: schedule,
    }),
  deleteSchedule: (id: string) =>
    http<{ status: string }>(`/api/schedules/${id}`, { method: "DELETE" }),
  triggerSchedule: (id: string) =>
    http<{ status: string; instance_id: string }>(`/api/schedules/${id}/trigger`, {
      method: "POST",
    }),

  // ---------------------------------------------------------------
  // Provider catalog + auth profiles (provider-catalog-and-oauth).
  //
  // Mirrors the HTTP surface added in internal/web/handlers_providers.go
  // and internal/web/handlers_profiles.go. Credential fields on profile
  // responses arrive masked from the server (internal/web/masks.go) —
  // the dashboard never touches plain-text credentials in the browser.
  // ---------------------------------------------------------------

  listProviders: () => http<CatalogEntry[]>("/api/providers"),
  createProvider: (entry: CatalogEntry) =>
    http<CatalogEntry>("/api/providers", { method: "POST", json: entry }),
  updateProvider: (id: string, entry: CatalogEntry) =>
    http<CatalogEntry>(`/api/providers/${encodeURIComponent(id)}`, {
      method: "PUT",
      json: entry,
    }),
  deleteProvider: (id: string) =>
    http<{ status: string }>(`/api/providers/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }),
  // The backend handler expects a JSON body of {"url":"https://..."}
  // identifying the openclaw catalog source. The dashboard surfaces
  // this as a single text input on the Providers tab — no default
  // is baked in (Requirement 3.3: the import is operator-triggered
  // and never automatic).
  importOpenclaw: (url: string) =>
    http<OpenclawImportResponse>("/api/providers/import-openclaw", {
      method: "POST",
      json: { url },
    }),

  listAuthProfiles: () => http<AuthProfile[]>("/api/auth/profiles"),
  createAPIKeyProfile: (req: {
    provider: string;
    profileId: string;
    apiKey: string;
    apiBaseOverride?: string;
  }) =>
    http<AuthProfile>("/api/auth/profiles/api-key", {
      method: "POST",
      json: req,
    }),
  oauthStart: (req: { provider: string; profileId?: string; preferPaste?: boolean }) =>
    http<OAuthStartResponse>("/api/auth/profiles/oauth/start", {
      method: "POST",
      json: req,
    }),
  oauthComplete: (req: {
    provider: string;
    flowId: string;
    code?: string;
    state?: string;
    setupToken?: string;
  }) =>
    http<AuthProfile>("/api/auth/profiles/oauth/complete", {
      method: "POST",
      json: req,
    }),
  refreshAuthProfile: (key: string) =>
    http<AuthProfile>(
      `/api/auth/profiles/${encodeURIComponent(key)}/refresh`,
      { method: "POST" },
    ),
  // Returns Promise<void>: the backend produces 204 No Content
  // on success and the wire response carries no body. Typing the
  // mutation as void (rather than the http<T>() generic default)
  // lets useDeleteAuthProfile's onSuccess callback skip data
  // handling entirely. M7.
  deleteAuthProfile: (key: string): Promise<void> =>
    http<void>(`/api/auth/profiles/${encodeURIComponent(key)}`, {
      method: "DELETE",
    }),

  // One-time legacy provider migration (provider-catalog-and-oauth, R15.4).
  // GET probe is read-only and idempotent — the dashboard polls it on
  // load to decide whether to render the migration banner. POST runs
  // the importer, which is gated server-side by the same eligibility
  // rules surfaced via the GET response.
  migrateLegacyStatus: () =>
    http<{ eligible: boolean; reason?: string }>(
      "/api/providers/migrate-legacy/status",
    ),
  migrateLegacy: () =>
    http<{ success: boolean }>("/api/providers/migrate-legacy", {
      method: "POST",
    }),
};
