// CatalogEditor — runtime CRUD UI for the LLM provider catalog
// surfaced under Settings → Providers (provider-catalog-and-oauth).
//
// The component lists every CatalogEntry returned from
// GET /api/providers, allows inline edits via a modal form that
// posts POST /api/providers (create) or PUT /api/providers/{id}
// (update), and supports per-row delete via DELETE
// /api/providers/{id}. The catalog ships empty (Requirement 1.8) —
// this editor is the operator's primary way to populate it without
// running the openclaw import.
//
// The form mirrors the on-disk Entry shape exactly (see
// internal/providers/types.go). `models` and `scopes` are entered
// as one-per-line textareas because that's the natural shape
// operators paste from vendor docs; the component normalizes those
// to string[] before posting. `id` is read-only on edit so the
// stable cache keys used by the profile store (R4.2) stay valid;
// renaming is achieved by deleting and recreating.
//
// Validates: Requirements 14.1, 14.3, 14.5.
import { useMemo, useState, type FormEvent } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ErrorState, EmptyState } from "@/components/states";
import { HttpError } from "@/api/client";
import {
  useCreateProvider,
  useDeleteProvider,
  useProviders,
  useUpdateProvider,
} from "@/api/queries";
import type { CatalogEntry } from "@/types/api";
import { Pencil, Plus, Trash2 } from "lucide-react";

// HEADER_STYLES mirrors providers.headerStyles in
// internal/providers/types.go. The backend rejects any other value
// with a 400 (Requirement 1.6); locking the picker here gives
// operators an authoritative list rather than a free-text guess.
const HEADER_STYLES: ReadonlyArray<CatalogEntry["headerStyle"]> = [
  "openai",
  "anthropic",
  "gemini",
];

// FLOWS mirrors the supported OAuth driver names registered in
// internal/auth/driver.go. Empty string means "API key only" — the
// driver registry is consulted only when this field is non-empty
// (R6.1, R7.1, R8.1, R9.1).
const FLOWS: ReadonlyArray<NonNullable<CatalogEntry["flow"]>> = [
  "",
  "pkce",
  "device_code",
  "setup_token",
  "claude_cli_reuse",
];

// FLOW_UNSET is a placeholder Select value because the underlying
// shadcn/ui Select disallows "" as a value — it conflates "" with
// "no selection". We translate "__none__" → "" on submit so the
// JSON payload still carries the documented empty-string
// (api-key-only) shape.
const FLOW_UNSET = "__none__";

interface FormState {
  id: string;
  displayName: string;
  baseURL: string;
  models: string;
  headerStyle: CatalogEntry["headerStyle"];
  flow: NonNullable<CatalogEntry["flow"]>;
  clientID: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  deviceAuthorizationEndpoint: string;
  scopes: string;
  audience: string;
}

const EMPTY_FORM: FormState = {
  id: "",
  displayName: "",
  baseURL: "",
  models: "",
  headerStyle: "openai",
  flow: "",
  clientID: "",
  authorizationEndpoint: "",
  tokenEndpoint: "",
  deviceAuthorizationEndpoint: "",
  scopes: "",
  audience: "",
};

function entryToForm(entry: CatalogEntry): FormState {
  return {
    id: entry.id,
    displayName: entry.displayName,
    baseURL: entry.baseURL,
    models: (entry.models ?? []).join("\n"),
    headerStyle: entry.headerStyle,
    flow: (entry.flow ?? "") as NonNullable<CatalogEntry["flow"]>,
    clientID: entry.clientID ?? "",
    authorizationEndpoint: entry.authorizationEndpoint ?? "",
    tokenEndpoint: entry.tokenEndpoint ?? "",
    deviceAuthorizationEndpoint: entry.deviceAuthorizationEndpoint ?? "",
    scopes: (entry.scopes ?? []).join("\n"),
    audience: entry.audience ?? "",
  };
}

// formToEntry normalizes textarea inputs into the array fields the
// backend expects, dropping blank lines so a stray newline at the
// end of a paste doesn't smuggle in an empty model id (which would
// then fail the regex check in providers.idRE).
function formToEntry(form: FormState): CatalogEntry {
  const splitLines = (raw: string) =>
    raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0);

  const entry: CatalogEntry = {
    id: form.id.trim(),
    displayName: form.displayName.trim(),
    baseURL: form.baseURL.trim(),
    headerStyle: form.headerStyle,
  };
  const models = splitLines(form.models);
  if (models.length > 0) entry.models = models;
  if (form.flow !== "") entry.flow = form.flow;
  if (form.clientID.trim() !== "") entry.clientID = form.clientID.trim();
  if (form.authorizationEndpoint.trim() !== "") {
    entry.authorizationEndpoint = form.authorizationEndpoint.trim();
  }
  if (form.tokenEndpoint.trim() !== "") {
    entry.tokenEndpoint = form.tokenEndpoint.trim();
  }
  if (form.deviceAuthorizationEndpoint.trim() !== "") {
    entry.deviceAuthorizationEndpoint = form.deviceAuthorizationEndpoint.trim();
  }
  const scopes = splitLines(form.scopes);
  if (scopes.length > 0) entry.scopes = scopes;
  if (form.audience.trim() !== "") entry.audience = form.audience.trim();
  return entry;
}

function errorMessage(err: unknown): string {
  if (err instanceof HttpError) {
    const data = err.data as { error?: string } | null | undefined;
    if (data?.error) return data.error;
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

export function CatalogEditor() {
  const providers = useProviders();
  const create = useCreateProvider();
  const update = useUpdateProvider();
  const del = useDeleteProvider();

  const [editing, setEditing] = useState<{
    mode: "create" | "edit";
    original?: CatalogEntry;
  } | null>(null);

  const sorted = useMemo(() => {
    const list = providers.data ?? [];
    // Catalog responses are unordered; sort on display name for a
    // stable UI. Ties (rare) fall back to id so the order remains
    // deterministic across re-fetches.
    return [...list].sort((a, b) => {
      const byName = a.displayName.localeCompare(b.displayName);
      if (byName !== 0) return byName;
      return a.id.localeCompare(b.id);
    });
  }, [providers.data]);

  if (providers.isLoading) return <Skeleton className="h-64" />;
  if (providers.error) {
    return (
      <ErrorState
        title="Failed to load providers"
        description={errorMessage(providers.error)}
        action={
          <Button size="sm" variant="outline" onClick={() => providers.refetch()}>
            Retry
          </Button>
        }
      />
    );
  }

  async function onDelete(entry: CatalogEntry) {
    const confirmed = window.confirm(
      `Delete provider "${entry.displayName}" (${entry.id})?\n\n` +
        "Existing credential profiles for this provider will be left in place but " +
        "will no longer be usable until the catalog entry is recreated.",
    );
    if (!confirmed) return;
    try {
      await del.mutateAsync(entry.id);
    } catch (err) {
      window.alert(errorMessage(err));
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3 pb-3">
        <div className="space-y-1">
          <CardTitle className="text-base">Provider catalog</CardTitle>
          <p className="text-xs text-muted-foreground">
            Persisted to <code className="font-mono">~/.xalgorix/data/providers.json</code>.
            Add, edit, or remove the LLM providers xalgorix can route scans to.
          </p>
        </div>
        <Button
          size="sm"
          onClick={() => setEditing({ mode: "create" })}
          disabled={create.isPending}
        >
          <Plus className="h-3.5 w-3.5" />
          Add provider
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {sorted.length === 0 ? (
          <div className="px-5 pb-5">
            <EmptyState
              title="No providers configured"
              description="Add a provider manually or import the openclaw catalog below to get started."
            />
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {sorted.map((entry) => (
              <li
                key={entry.id}
                className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-medium">{entry.displayName}</p>
                    <code className="font-mono text-xs text-muted-foreground">
                      {entry.id}
                    </code>
                    <Badge variant="outline">{entry.headerStyle}</Badge>
                    {entry.flow && <Badge>{entry.flow}</Badge>}
                  </div>
                  <p className="break-all font-mono text-xs text-muted-foreground">
                    {entry.baseURL}
                  </p>
                  {entry.models && entry.models.length > 0 && (
                    <p className="text-xs text-muted-foreground">
                      <span className="font-medium">Models:</span>{" "}
                      <span className="font-mono">
                        {entry.models.slice(0, 4).join(", ")}
                        {entry.models.length > 4
                          ? ` +${entry.models.length - 4} more`
                          : ""}
                      </span>
                    </p>
                  )}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setEditing({ mode: "edit", original: entry })}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="destructive"
                    onClick={() => onDelete(entry)}
                    disabled={del.isPending}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {editing && (
        <CatalogEntryDialog
          mode={editing.mode}
          original={editing.original}
          onClose={() => setEditing(null)}
          onSubmitCreate={(entry) => create.mutateAsync(entry)}
          onSubmitUpdate={(id, entry) => update.mutateAsync({ id, entry })}
          submitting={create.isPending || update.isPending}
        />
      )}
    </Card>
  );
}

function CatalogEntryDialog({
  mode,
  original,
  onClose,
  onSubmitCreate,
  onSubmitUpdate,
  submitting,
}: {
  mode: "create" | "edit";
  original?: CatalogEntry;
  onClose: () => void;
  onSubmitCreate: (entry: CatalogEntry) => Promise<unknown>;
  onSubmitUpdate: (id: string, entry: CatalogEntry) => Promise<unknown>;
  submitting: boolean;
}) {
  const [form, setForm] = useState<FormState>(
    original ? entryToForm(original) : EMPTY_FORM,
  );
  const [error, setError] = useState<string | null>(null);

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const entry = formToEntry(form);
      if (mode === "create") {
        await onSubmitCreate(entry);
      } else if (original) {
        await onSubmitUpdate(original.id, entry);
      }
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  const title = mode === "create" ? "Add provider" : `Edit ${original?.displayName ?? ""}`;
  const description =
    mode === "create"
      ? "Define a new LLM provider entry. id, display name, base URL, and header style are required."
      : "Update the provider definition. The id cannot be changed; delete and recreate to rename.";

  return (
    <Dialog
      open
      onOpenChange={(next) => {
        if (!next) onClose();
      }}
    >
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="max-h-[70vh] space-y-4 overflow-y-auto pr-1">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="catalog-id">Id</Label>
              <Input
                id="catalog-id"
                value={form.id}
                onChange={(e) => update("id", e.target.value)}
                placeholder="openai"
                required
                disabled={mode === "edit"}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Lowercase letters, digits, hyphen, or underscore.
              </p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="catalog-display">Display name</Label>
              <Input
                id="catalog-display"
                value={form.displayName}
                onChange={(e) => update("displayName", e.target.value)}
                placeholder="OpenAI"
                required
              />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="catalog-base">Base URL</Label>
              <Input
                id="catalog-base"
                value={form.baseURL}
                onChange={(e) => update("baseURL", e.target.value)}
                placeholder="https://api.openai.com/v1"
                required
                className="font-mono"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="catalog-header-style">Header style</Label>
              <Select
                value={form.headerStyle}
                onValueChange={(value) =>
                  update(
                    "headerStyle",
                    value as CatalogEntry["headerStyle"],
                  )
                }
              >
                <SelectTrigger id="catalog-header-style">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {HEADER_STYLES.map((style) => (
                    <SelectItem key={style} value={style}>
                      {style}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="catalog-models">Models (one per line)</Label>
            <Textarea
              id="catalog-models"
              value={form.models}
              onChange={(e) => update("models", e.target.value)}
              rows={4}
              placeholder={"gpt-5\ngpt-5-mini"}
              className="font-mono text-xs"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="catalog-flow">OAuth flow</Label>
            <Select
              value={form.flow === "" ? FLOW_UNSET : form.flow}
              onValueChange={(value) =>
                update(
                  "flow",
                  value === FLOW_UNSET
                    ? ""
                    : (value as NonNullable<CatalogEntry["flow"]>),
                )
              }
            >
              <SelectTrigger id="catalog-flow">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={FLOW_UNSET}>none (API key only)</SelectItem>
                {FLOWS.filter((flow) => flow !== "").map((flow) => (
                  <SelectItem key={flow} value={flow}>
                    {flow}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Leave as "none" for providers that authenticate with a static API
              key. Selecting a flow enables the matching "Sign in with…" button
              under the profile list.
            </p>
          </div>
          {form.flow !== "" && (
            <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3">
              <p className="text-xs font-medium text-muted-foreground">
                OAuth metadata
              </p>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="catalog-client-id">Client id</Label>
                  <Input
                    id="catalog-client-id"
                    value={form.clientID}
                    onChange={(e) => update("clientID", e.target.value)}
                    placeholder="xalgorix-codex"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="catalog-audience">Audience (optional)</Label>
                  <Input
                    id="catalog-audience"
                    value={form.audience}
                    onChange={(e) => update("audience", e.target.value)}
                    placeholder=""
                    className="font-mono"
                  />
                </div>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="catalog-auth-endpoint">
                    Authorization endpoint
                  </Label>
                  <Input
                    id="catalog-auth-endpoint"
                    value={form.authorizationEndpoint}
                    onChange={(e) =>
                      update("authorizationEndpoint", e.target.value)
                    }
                    placeholder="https://auth.example.com/oauth/authorize"
                    className="font-mono"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="catalog-token-endpoint">Token endpoint</Label>
                  <Input
                    id="catalog-token-endpoint"
                    value={form.tokenEndpoint}
                    onChange={(e) => update("tokenEndpoint", e.target.value)}
                    placeholder="https://auth.example.com/oauth/token"
                    className="font-mono"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="catalog-device-endpoint">
                  Device authorization endpoint
                </Label>
                <Input
                  id="catalog-device-endpoint"
                  value={form.deviceAuthorizationEndpoint}
                  onChange={(e) =>
                    update("deviceAuthorizationEndpoint", e.target.value)
                  }
                  placeholder="https://auth.example.com/oauth/device"
                  className="font-mono"
                />
                <p className="text-xs text-muted-foreground">
                  Required only for the device-code flow.
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="catalog-scopes">Scopes (one per line)</Label>
                <Textarea
                  id="catalog-scopes"
                  value={form.scopes}
                  onChange={(e) => update("scopes", e.target.value)}
                  rows={3}
                  placeholder={"chat\nmodels.read"}
                  className="font-mono text-xs"
                />
              </div>
            </div>
          )}
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting
                ? "Saving…"
                : mode === "create"
                  ? "Create provider"
                  : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default CatalogEditor;
