// ProvidersTab — composite Settings tab for the
// provider-catalog-and-oauth feature. Bundles the runtime catalog
// editor, the credential profile list, and the optional openclaw
// import action into a single panel under Settings → Providers
// (Requirement 14.1).
//
// Each section is rendered as its own Card so the tab reads as a
// sequence of independent capabilities rather than one monolithic
// form. The OpenclawImport panel sits below the catalog editor by
// design — operators typically populate the catalog manually first,
// reach for the import only when they want a starting set, and
// then return to credentials once entries exist.
//
// Validates: Requirements 14.1, 14.2, 14.3, 14.5.
import CatalogEditor from "./catalog-editor";
import LegacyMigrationBanner from "./legacy-migration-banner";
import OpenclawImport from "./openclaw-import";
import ProfileList from "./profile-list";

export function ProvidersTab() {
  return (
    <div className="space-y-4">
      <LegacyMigrationBanner />
      <CatalogEditor />
      <OpenclawImport />
      <div className="space-y-3">
        <div>
          <h2 className="text-sm font-semibold">Credential profiles</h2>
          <p className="text-xs text-muted-foreground">
            Stored credentials per provider. Tokens are masked once persisted —
            xalgorix only sees plaintext credentials at write time.
          </p>
        </div>
        <ProfileList />
      </div>
    </div>
  );
}

export default ProvidersTab;
