// ProfileList — runtime-editable credential profile list grouped by
// provider. Backs the new Settings → Providers tab introduced by the
// provider-catalog-and-oauth feature.
//
// Behavior:
//
//   • Loads the catalog (`/api/providers`) and profile list
//     (`/api/auth/profiles`) and groups profiles by provider id.
//     The catalog drives the section headers (so an unconfigured
//     provider can still surface "Add API key") and is consulted to
//     decide whether to render the "Sign in with <displayName>"
//     button — only catalog entries with a non-empty `flow` field
//     get one (Requirement 14.2).
//
//   • Renders credential strings exactly as the server returned
//     them. The /api/auth/profiles handler masks apiKey,
//     accessToken, and refreshToken via maskAuthCredential
//     (internal/web/masks.go) so the dashboard never sees a plaintext
//     credential. Requirements 5.1, 5.2, 14.5.
//
//   • Action buttons per profile / provider:
//       - "Add API key" → opens a small dialog that posts to
//         `/api/auth/profiles/api-key`.
//       - "Sign in with <displayName>" → opens the OAuth modal
//         (oauth-modal.tsx) which dispatches the loopback / device /
//         paste UI based on the start response.
//       - "Refresh token" → only for OAuth profiles, posts to
//         `/api/auth/profiles/{key}/refresh`.
//       - "Delete profile" → confirmed `window.confirm`, then DELETE
//         `/api/auth/profiles/{key}`.
//
// Validates: Requirements 5.1, 5.2, 14.1, 14.2, 14.5.
import { useMemo, useState, type FormEvent } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ErrorState, EmptyState } from "@/components/states";
import { HttpError } from "@/api/client";
import {
  useAuthProfiles,
  useCreateAPIKeyProfile,
  useDeleteAuthProfile,
  useProviders,
  useRefreshAuthProfile,
} from "@/api/queries";
import type { AuthProfile, CatalogEntry } from "@/types/api";
import { Plus, RefreshCw, Trash2, KeyRound, LogIn } from "lucide-react";
import OAuthModal from "./oauth-modal";

function errorMessage(err: unknown): string {
  if (err instanceof HttpError) {
    const data = err.data as { error?: string } | null | undefined;
    if (data?.error) return data.error;
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

// providerHeading maps a provider id to its catalog displayName,
// falling back to the raw id when the catalog has no matching entry
// (this happens when a profile references a provider that was later
// deleted from the catalog — the profile is still listed but the
// "Sign in with…" button is suppressed).
function providerHeading(id: string, catalog: CatalogEntry[] | undefined): string {
  const entry = catalog?.find((e) => e.id === id);
  if (entry?.displayName) return entry.displayName;
  return id;
}

function catalogEntry(
  id: string,
  catalog: CatalogEntry[] | undefined,
): CatalogEntry | undefined {
  return catalog?.find((e) => e.id === id);
}

// groupProfiles bins the flat /api/auth/profiles array by provider
// id while preserving the catalog order so the UI is stable across
// renders. Providers from the catalog that have zero profiles are
// included so the "Add API key" / "Sign in with…" buttons surface
// without the operator having to create a profile first.
function groupProfiles(
  profiles: AuthProfile[],
  catalog: CatalogEntry[],
): Array<{ provider: string; profiles: AuthProfile[] }> {
  const byProvider = new Map<string, AuthProfile[]>();
  for (const p of profiles) {
    const list = byProvider.get(p.provider) ?? [];
    list.push(p);
    byProvider.set(p.provider, list);
  }
  const groups: Array<{ provider: string; profiles: AuthProfile[] }> = [];
  const seen = new Set<string>();
  for (const entry of catalog) {
    groups.push({
      provider: entry.id,
      profiles: byProvider.get(entry.id) ?? [],
    });
    seen.add(entry.id);
  }
  // Tail any orphan profiles whose provider is no longer in the
  // catalog so the operator can still see and delete them.
  for (const [provider, list] of byProvider.entries()) {
    if (!seen.has(provider)) {
      groups.push({ provider, profiles: list });
    }
  }
  return groups;
}

export function ProfileList() {
  const profiles = useAuthProfiles();
  const providers = useProviders();
  const refresh = useRefreshAuthProfile();
  const del = useDeleteAuthProfile();

  const [apiKeyTarget, setApiKeyTarget] = useState<string | null>(null);
  const [oauthTarget, setOauthTarget] = useState<{
    provider: string;
    displayName: string;
  } | null>(null);

  const groups = useMemo(() => {
    return groupProfiles(profiles.data ?? [], providers.data ?? []);
  }, [profiles.data, providers.data]);

  const existingKeys = useMemo(
    () => (profiles.data ?? []).map((p) => `${p.provider}:${p.profileId}`),
    [profiles.data],
  );

  const isLoading = profiles.isLoading || providers.isLoading;
  const errorState = profiles.error ?? providers.error;

  if (isLoading) return <Skeleton className="h-64" />;
  if (errorState) {
    return (
      <ErrorState
        title="Failed to load credential profiles"
        description={errorMessage(errorState)}
        action={
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              profiles.refetch();
              providers.refetch();
            }}
          >
            Retry
          </Button>
        }
      />
    );
  }

  if (groups.length === 0) {
    return (
      <EmptyState
        title="No providers configured"
        description="Add a provider to the catalog before storing credentials."
      />
    );
  }

  async function onDelete(key: string) {
    if (!window.confirm(`Delete profile ${key}? This cannot be undone.`)) {
      return;
    }
    try {
      await del.mutateAsync(key);
    } catch (err) {
      window.alert(errorMessage(err));
    }
  }

  async function onRefresh(key: string) {
    try {
      await refresh.mutateAsync(key);
    } catch (err) {
      window.alert(errorMessage(err));
    }
  }

  return (
    <div className="space-y-4">
      {groups.map((group) => {
        const entry = catalogEntry(group.provider, providers.data);
        const heading = providerHeading(group.provider, providers.data);
        const showOAuth = !!entry && !!entry.flow;
        return (
          <Card key={group.provider}>
            <CardHeader className="flex flex-row items-center justify-between gap-3 pb-3">
              <div className="space-y-1">
                <CardTitle className="text-base">{heading}</CardTitle>
                <p className="font-mono text-xs text-muted-foreground">
                  {group.provider}
                  {entry?.headerStyle ? ` · ${entry.headerStyle}` : ""}
                  {entry?.flow ? ` · ${entry.flow}` : ""}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setApiKeyTarget(group.provider)}
                >
                  <Plus className="h-3.5 w-3.5" />
                  Add API key
                </Button>
                {showOAuth && (
                  <Button
                    size="sm"
                    onClick={() =>
                      setOauthTarget({
                        provider: group.provider,
                        displayName: heading,
                      })
                    }
                  >
                    <LogIn className="h-3.5 w-3.5" />
                    Sign in with {heading}
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {group.profiles.length === 0 ? (
                <p className="border-t border-border px-5 py-4 text-xs text-muted-foreground">
                  No profiles yet for this provider.
                </p>
              ) : (
                <ul className="divide-y divide-border">
                  {group.profiles.map((p) => (
                    <ProfileRow
                      key={`${p.provider}:${p.profileId}`}
                      profile={p}
                      onDelete={() => onDelete(`${p.provider}:${p.profileId}`)}
                      onRefresh={() =>
                        onRefresh(`${p.provider}:${p.profileId}`)
                      }
                      refreshing={refresh.isPending}
                      deleting={del.isPending}
                    />
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        );
      })}

      <AddAPIKeyDialog
        provider={apiKeyTarget}
        onClose={() => setApiKeyTarget(null)}
      />

      {oauthTarget && (
        <OAuthModal
          open={!!oauthTarget}
          provider={oauthTarget.provider}
          displayName={oauthTarget.displayName}
          existingKeys={existingKeys}
          onClose={() => setOauthTarget(null)}
        />
      )}
    </div>
  );
}

function ProfileRow({
  profile,
  onDelete,
  onRefresh,
  refreshing,
  deleting,
}: {
  profile: AuthProfile;
  onDelete: () => void;
  onRefresh: () => void;
  refreshing: boolean;
  deleting: boolean;
}) {
  const isOAuth = profile.type === "oauth";
  const credential = isOAuth ? profile.accessToken : profile.apiKey;
  const expires = profile.expiresAt
    ? new Date(profile.expiresAt).toLocaleString()
    : null;
  return (
    <li className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      <div className="min-w-0 space-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="font-mono text-sm">
            {profile.provider}:{profile.profileId}
          </p>
          <Badge variant={isOAuth ? "default" : "outline"}>
            {isOAuth ? "OAuth" : "API key"}
          </Badge>
          {profile.requiresReauth && (
            <Badge variant="warning">requires re-auth</Badge>
          )}
        </div>
        <p className="font-mono text-xs text-muted-foreground">
          <KeyRound className="mr-1 inline h-3 w-3" />
          {credential || "—"}
        </p>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {expires && <span>expires {expires}</span>}
          {profile.tokenType && <span>type {profile.tokenType}</span>}
          {profile.scopes && profile.scopes.length > 0 && (
            <span>scopes {profile.scopes.join(" ")}</span>
          )}
          {profile.apiBaseOverride && (
            <span>base override {profile.apiBaseOverride}</span>
          )}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {isOAuth && (
          <Button
            size="sm"
            variant="outline"
            onClick={onRefresh}
            disabled={refreshing}
          >
            <RefreshCw className="h-3.5 w-3.5" />
            {refreshing ? "Refreshing…" : "Refresh"}
          </Button>
        )}
        <Button
          size="sm"
          variant="destructive"
          onClick={onDelete}
          disabled={deleting}
        >
          <Trash2 className="h-3.5 w-3.5" />
          Delete
        </Button>
      </div>
    </li>
  );
}

function AddAPIKeyDialog({
  provider,
  onClose,
}: {
  provider: string | null;
  onClose: () => void;
}) {
  const create = useCreateAPIKeyProfile();
  const [profileId, setProfileId] = useState("default");
  const [apiKey, setApiKey] = useState("");
  const [apiBaseOverride, setApiBaseOverride] = useState("");
  const [error, setError] = useState<string | null>(null);

  const open = !!provider;

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!provider) return;
    setError(null);
    try {
      await create.mutateAsync({
        provider,
        profileId: profileId.trim() || "default",
        apiKey: apiKey.trim(),
        apiBaseOverride: apiBaseOverride.trim() || undefined,
      });
      setProfileId("default");
      setApiKey("");
      setApiBaseOverride("");
      onClose();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setProfileId("default");
          setApiKey("");
          setApiBaseOverride("");
          setError(null);
          onClose();
        }
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add API key</DialogTitle>
          <DialogDescription>
            Stored as
            <span className="ml-1 font-mono">
              {provider}:{profileId.trim() || "default"}
            </span>
            . The key is masked on every subsequent read.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={onSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="apikey-profile-id">Profile id</Label>
            <Input
              id="apikey-profile-id"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              placeholder="default"
              required
              className="font-mono"
            />
            <p className="text-xs text-muted-foreground">
              Lowercase letters, digits, hyphen, or underscore.
            </p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="apikey-value">API key</Label>
            <Input
              id="apikey-value"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              required
              className="font-mono"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="apikey-base">API base override (optional)</Label>
            <Input
              id="apikey-base"
              value={apiBaseOverride}
              onChange={(e) => setApiBaseOverride(e.target.value)}
              placeholder="https://example.com/v1"
              className="font-mono"
            />
          </div>
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {error}
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={create.isPending || apiKey.trim() === ""}
            >
              {create.isPending ? "Saving…" : "Save API key"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default ProfileList;
