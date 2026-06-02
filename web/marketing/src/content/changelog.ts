/**
 * Static changelog source for `/changelog` (Requirement 16.1).
 *
 * Each entry is rendered as a Markdown-style list item by
 * `app/changelog/page.tsx`. Keep entries newest-first. Categories
 * mirror Requirement 16.1: `new`, `improved`, `fixed`, `security`.
 *
 * The page is regenerated every hour (`revalidate = 3600`) so adding
 * a new entry to this file and redeploying is sufficient — there is
 * no CMS or runtime fetch.
 */

export type ChangelogCategory = "new" | "improved" | "fixed" | "security";

export type ChangelogEntry = {
  /** ISO 8601 date (YYYY-MM-DD) the entry was published. */
  date: string;
  title: string;
  category: ChangelogCategory;
  /** Plain-text summary; one to three sentences. */
  summary: string;
};

export const changelogEntries: readonly ChangelogEntry[] = [
  {
    date: "2026-01-01",
    title: "Initial preview",
    category: "new",
    summary:
      "Initial preview release of the Xalgorix Cloud marketing site. Detailed customer-visible release notes will be published here as the platform ships.",
  },
];
