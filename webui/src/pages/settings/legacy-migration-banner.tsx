// LegacyMigrationBanner — one-time confirmation banner for the
// provider-catalog-and-oauth feature (Wave G task 7.2).
//
// Behavior mirrors the design doc's Migration section: when the
// server reports `eligible: true` from
// GET /api/providers/migrate-legacy/status, we render a banner
// inviting the operator to convert their existing
// XALGORIX_LLM / XALGORIX_API_KEY / XALGORIX_API_BASE values into
// a Catalog_Entry (id="legacy") + API_Key_Profile (legacy:default).
//
// On confirm we POST /api/providers/migrate-legacy, which on success
// writes the sentinel ~/.xalgorix/data/.legacy-providers-migrated so
// the banner never reappears across restarts. The success handler
// invalidates the providers + authProfiles + migrateLegacy query
// caches so the rest of the Providers tab reflects the new entry
// immediately.
//
// On dismiss we just hide the banner for the current browser
// session via local state — the server-side sentinel still gates
// future renders, so an operator who reloads tomorrow without
// having migrated will see the banner again. This keeps "dismiss"
// as a soft, recoverable action while leaving "Migrate now" as the
// permanent decision.
//
// Mounted inside ProvidersTab so it only surfaces once the operator
// opens Settings → Providers (Requirement 14.1). It deliberately
// does not render on /overview the way LegacyImportBanner does for
// the older scan-import flow — the migration is provider-tab
// scoped and we'd rather let the operator find it in context.
//
// Validates: Requirements 14.1, 14.5, 15.4.
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { HttpError } from "@/api/client";
import {
  useMigrateLegacy,
  useMigrateLegacyStatus,
} from "@/api/queries";
import { toast } from "sonner";
import { ArrowRightLeft } from "lucide-react";

function errorMessage(err: unknown): string {
  if (err instanceof HttpError) {
    const data = err.data as { error?: string } | null | undefined;
    if (data?.error) return data.error;
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

export function LegacyMigrationBanner() {
  const status = useMigrateLegacyStatus();
  const migrate = useMigrateLegacy();

  // Session-only dismiss — staying out of localStorage on purpose
  // so a fresh tab still sees the banner when eligibility hasn't
  // changed (the sentinel is the durable gate).
  const [dismissed, setDismissed] = useState(false);

  // While the eligibility probe is loading we render nothing — a
  // brief gap is preferable to a banner that flashes in and then
  // disappears. The same pattern is used by LegacyImportBanner.
  if (status.isLoading) return null;
  if (status.error) return null;
  if (!status.data?.eligible) return null;
  if (dismissed) return null;

  async function onConfirm() {
    try {
      await migrate.mutateAsync();
      toast.success("Legacy LLM settings migrated", {
        description:
          "Created provider entry “legacy” and profile legacy:default.",
      });
    } catch (err) {
      toast.error("Migration failed", {
        description: errorMessage(err),
      });
    }
  }

  return (
    <Card className="border-primary/40 bg-primary/5">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <ArrowRightLeft className="h-4 w-4 text-primary" />
          Migrate your legacy LLM settings
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          We can import your existing{" "}
          <code className="rounded bg-background/60 px-1 font-mono">
            XALGORIX_LLM
          </code>{" "}
          /{" "}
          <code className="rounded bg-background/60 px-1 font-mono">
            XALGORIX_API_KEY
          </code>{" "}
          values into the new provider catalog as a single{" "}
          <span className="font-medium">legacy</span> provider entry plus an
          API-key profile keyed{" "}
          <code className="rounded bg-background/60 px-1 font-mono">
            legacy:default
          </code>
          . Your env file is left untouched, so the existing free-text
          Settings form keeps working exactly as before.
        </p>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDismissed(true)}
            disabled={migrate.isPending}
          >
            Dismiss
          </Button>
          <Button
            size="sm"
            onClick={onConfirm}
            disabled={migrate.isPending}
          >
            {migrate.isPending ? "Migrating…" : "Migrate now"}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default LegacyMigrationBanner;
