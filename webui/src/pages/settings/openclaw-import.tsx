// OpenclawImport — single-action panel that triggers
// POST /api/providers/import-openclaw with an operator-supplied URL
// and renders the per-entry outcomes envelope returned by the
// backend (provider-catalog-and-oauth, Requirement 14.3).
//
// The catalog ships empty (Requirement 1.8) and the import is
// strictly opt-in: no startup fetch, no scheduled task (Requirement
// 3.3). The backend handler at internal/web/handlers_providers.go
// expects {"url":"https://..."} and replies with either the
// {outcomes:[{id,action,reason?}]} envelope on success or an HTTP
// 502 with {statusCode, body} when the upstream fetch fails
// (Requirement 3.4). This component surfaces both shapes.
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 14.3.
import { useState, type FormEvent } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { HttpError } from "@/api/client";
import { useImportOpenclaw } from "@/api/queries";
import type { OpenclawImportResponse } from "@/types/api";
import { Download } from "lucide-react";

// UpstreamErrorEnvelope mirrors the {statusCode, body} JSON shape
// returned at HTTP 502 by internal/web/handlers_providers.go when
// the upstream fetch returns a non-2xx response.
interface UpstreamErrorEnvelope {
  statusCode?: number;
  body?: string;
}

function isUpstreamErrorEnvelope(value: unknown): value is UpstreamErrorEnvelope {
  if (!value || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  return "statusCode" in v || "body" in v;
}

interface ErrorView {
  message: string;
  upstream?: UpstreamErrorEnvelope;
}

function describeError(err: unknown): ErrorView {
  if (err instanceof HttpError) {
    if (err.status === 502 && isUpstreamErrorEnvelope(err.data)) {
      return {
        message: "Upstream openclaw fetch failed",
        upstream: err.data,
      };
    }
    const data = err.data as { error?: string } | null | undefined;
    if (data?.error) return { message: data.error };
    return { message: err.message };
  }
  if (err instanceof Error) return { message: err.message };
  return { message: "Unknown error" };
}

export function OpenclawImport() {
  const importMutation = useImportOpenclaw();

  const [url, setUrl] = useState("");
  const [result, setResult] = useState<OpenclawImportResponse | null>(null);
  const [error, setError] = useState<ErrorView | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (trimmed === "") return;

    // H8 client-side gate: render the parsed host in a confirm
    // prompt before issuing the POST. The import gives the
    // configured upstream the operator's future OAuth grants
    // (anyone editing the catalog through the dashboard is
    // implicitly trusted, but a typo into a malicious
    // openclaw mirror should still produce a "wait, did you
    // mean…" pause). window.confirm is the same affordance the
    // dashboard uses for other one-click destructive actions
    // (e.g., delete profile); using a richer dialog component
    // is a follow-up that does not change the contract here.
    let host = "";
    try {
      host = new URL(trimmed).host;
    } catch {
      // Invalid URL — let the server's HTTPS scheme check
      // produce the canonical 400 envelope rather than
      // double-validating in the client.
    }
    const proceed = window.confirm(
      `Import providers from ${host || trimmed}? They'll receive your future OAuth grants.`,
    );
    if (!proceed) return;

    setError(null);
    setResult(null);
    try {
      const response = await importMutation.mutateAsync(trimmed);
      setResult(response);
    } catch (err) {
      setError(describeError(err));
    }
  }

  const importedCount =
    result?.outcomes.filter((o) => o.action === "imported").length ?? 0;
  const skippedCount =
    result?.outcomes.filter((o) => o.action === "skipped").length ?? 0;

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Import openclaw catalog</CardTitle>
        <p className="text-xs text-muted-foreground">
          Fetches the openclaw provider directory over HTTPS and merges entries
          into your local catalog. Entries with an id that already exists
          locally are kept unchanged. The fetch only happens when you click
          Import — there is no automatic background sync.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={onSubmit} className="space-y-3">
          <div className="space-y-2">
            <Label htmlFor="openclaw-url">openclaw catalog URL</Label>
            <Input
              id="openclaw-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://raw.githubusercontent.com/openclaw/catalog/main/providers.json"
              required
              type="url"
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Provide the URL of an openclaw-compatible providers JSON document.
            </p>
          </div>
          <div className="flex justify-end">
            <Button
              type="submit"
              disabled={importMutation.isPending || url.trim() === ""}
            >
              <Download className="h-3.5 w-3.5" />
              {importMutation.isPending
                ? "Importing…"
                : "Import openclaw catalog"}
            </Button>
          </div>
        </form>

        {error && (
          <div className="space-y-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
            <p className="font-medium">{error.message}</p>
            {error.upstream && (
              <div className="space-y-1 text-xs">
                {typeof error.upstream.statusCode === "number" && (
                  <p>
                    <span className="font-mono">
                      HTTP {error.upstream.statusCode}
                    </span>{" "}
                    from upstream.
                  </p>
                )}
                {error.upstream.body && (
                  <pre className="max-h-48 overflow-auto rounded border border-destructive/20 bg-background/40 p-2 font-mono text-[11px] leading-relaxed text-foreground">
                    {error.upstream.body}
                  </pre>
                )}
              </div>
            )}
          </div>
        )}

        {result && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <p className="font-medium">Import complete</p>
              <Badge variant="success">{importedCount} imported</Badge>
              <Badge variant="muted">{skippedCount} skipped</Badge>
            </div>
            {result.outcomes.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                Upstream returned an empty catalog — nothing was changed.
              </p>
            ) : (
              <ul className="divide-y divide-border rounded-md border border-border">
                {result.outcomes.map((outcome) => (
                  <li
                    key={`${outcome.id}-${outcome.action}`}
                    className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs"
                  >
                    <code className="font-mono">{outcome.id}</code>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          outcome.action === "imported" ? "success" : "muted"
                        }
                      >
                        {outcome.action}
                      </Badge>
                      {outcome.reason && (
                        <span className="text-muted-foreground">
                          {outcome.reason}
                        </span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default OpenclawImport;
